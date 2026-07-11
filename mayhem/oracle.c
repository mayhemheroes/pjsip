/*
 * pjsip/mayhem/oracle.c — self-contained golden oracle over the EXACT parse paths the
 * mayhem harnesses fuzz. No network, no devices, no test framework: it drives
 *   pjsip_parse_msg / pjsip_parse_uri   (fuzz-sip path,  pjsip)
 *   pjmedia_sdp_parse                   (fuzz-sdp path,  pjmedia)
 *   pj_stun_msg_decode                  (fuzz-stun path, pjnath)
 *   pj_xml_parse / pj_xml_print         (fuzz-xml path,  pjlib-util)
 * with known-GOOD inputs (must parse) and known-BAD inputs (must be rejected), asserting the
 * documented result. A no-op / "always succeed" or "always fail" patch to any parser flips at
 * least one case, so this is a real PATCH-grade oracle — not a stub. Built with NORMAL (non-fuzz)
 * flags by mayhem/build-tests + run by mayhem/test.sh; emits one PASS/FAIL line per case.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjsip.h>
#include <pjmedia.h>
#include <pjmedia/sdp.h>
#include <pjnath.h>

static pj_caching_pool g_cp;
static pjsip_endpoint *g_endpt;
static int g_pass = 0, g_fail = 0;

static void ok(const char *name, int cond)
{
    if (cond) { g_pass++; printf("PASS %s\n", name); }
    else      { g_fail++; printf("FAIL %s\n", name); }
}

static pj_pool_t *pool_new(const char *n)
{
    return pj_pool_create(&g_cp.factory, n, 4096, 4096, NULL);
}

/* ---- fuzz-sip: SIP message + URI parsing ---- */
static void test_sip(void)
{
    static const char GOOD_MSG[] =
        "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
        "Max-Forwards: 70\r\n"
        "To: Bob <sip:bob@biloxi.example.com>\r\n"
        "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
        "CSeq: 314159 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    /* garbage start line: not a valid SIP request/status line */
    static const char BAD_MSG[] = "%%%not a sip message%%%\r\n\r\n";

    pj_pool_t *pool = pool_new("sip");
    char *buf;
    pjsip_msg *msg;

    buf = pj_pool_alloc(pool, sizeof(GOOD_MSG));
    pj_memcpy(buf, GOOD_MSG, sizeof(GOOD_MSG));
    msg = pjsip_parse_msg(pool, buf, sizeof(GOOD_MSG) - 1, NULL);
    ok("sip.msg.good_parses", msg != NULL && msg->type == PJSIP_REQUEST_MSG);
    ok("sip.msg.good_method_invite",
       msg != NULL && msg->line.req.method.id == PJSIP_INVITE_METHOD);

    buf = pj_pool_alloc(pool, sizeof(BAD_MSG));
    pj_memcpy(buf, BAD_MSG, sizeof(BAD_MSG));
    msg = pjsip_parse_msg(pool, buf, sizeof(BAD_MSG) - 1, NULL);
    ok("sip.msg.bad_rejected", msg == NULL);

    /* URI parsing */
    {
        char uri_good[] = "sip:alice@atlanta.example.com;transport=tcp";
        char uri_bad[]  = "this is not a uri";
        pjsip_uri *u;
        u = pjsip_parse_uri(pool, uri_good, sizeof(uri_good) - 1, 0);
        ok("sip.uri.good_parses", u != NULL);
        u = pjsip_parse_uri(pool, uri_bad, sizeof(uri_bad) - 1, 0);
        ok("sip.uri.bad_rejected", u == NULL);
    }

    pj_pool_release(pool);
}

/* ---- fuzz-sdp: SDP body parsing ---- */
static void test_sdp(void)
{
    static const char GOOD[] =
        "v=0\r\n"
        "o=alice 2890844526 2890844526 IN IP4 host.example.com\r\n"
        "s=session\r\n"
        "c=IN IP4 host.example.com\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 0 8\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n";
    /* missing mandatory v=/o=/s=/t= lines */
    static const char BAD[] = "garbage=line\r\nnot sdp at all\r\n";

    pj_pool_t *pool = pool_new("sdp");
    pjmedia_sdp_session *sdp;
    char *buf;
    pj_status_t st;

    buf = pj_pool_alloc(pool, sizeof(GOOD));
    pj_memcpy(buf, GOOD, sizeof(GOOD));
    st = pjmedia_sdp_parse(pool, buf, sizeof(GOOD) - 1, &sdp);
    ok("sdp.good_parses", st == PJ_SUCCESS && sdp != NULL);
    ok("sdp.good_one_media", st == PJ_SUCCESS && sdp != NULL && sdp->media_count == 1);
    if (st == PJ_SUCCESS && sdp)
        ok("sdp.good_validates", pjmedia_sdp_validate(sdp) == PJ_SUCCESS);
    else
        ok("sdp.good_validates", 0);

    buf = pj_pool_alloc(pool, sizeof(BAD));
    pj_memcpy(buf, BAD, sizeof(BAD));
    st = pjmedia_sdp_parse(pool, buf, sizeof(BAD) - 1, &sdp);
    ok("sdp.bad_rejected", st != PJ_SUCCESS);

    pj_pool_release(pool);
}

/* ---- fuzz-stun: STUN message decoding ---- */
static void test_stun(void)
{
    /* RFC 5389 Binding Request: type=0x0001, len=0x0000, magic 2112A442, 12-byte txn id */
    static const pj_uint8_t GOOD[20] = {
        0x00, 0x01, 0x00, 0x00,
        0x21, 0x12, 0xA4, 0x42,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
    };
    /* Structurally invalid: header declares a 0x0100-byte body but only 8 body bytes follow,
     * so the message-length / attribute walk overruns the PDU and decode must fail. */
    static const pj_uint8_t BAD[20] = {
        0x00, 0x01, 0x01, 0x00,
        0x21, 0x12, 0xA4, 0x42,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
    };
    pj_pool_t *pool = pool_new("stun");
    pj_stun_msg *msg;
    pj_status_t st;

    st = pj_stun_msg_decode(pool, GOOD, sizeof(GOOD),
                            PJ_STUN_CHECK_PACKET, &msg, NULL, NULL);
    ok("stun.good_decodes", st == PJ_SUCCESS && msg != NULL);
    ok("stun.good_is_binding_req",
       st == PJ_SUCCESS && msg != NULL && msg->hdr.type == PJ_STUN_BINDING_REQUEST);

    st = pj_stun_msg_decode(pool, BAD, sizeof(BAD),
                            PJ_STUN_CHECK_PACKET, &msg, NULL, NULL);
    ok("stun.bad_rejected", st != PJ_SUCCESS);

    pj_pool_release(pool);
}

/* ---- fuzz-xml: XML parsing + printing ---- */
static void test_xml(void)
{
    static const char GOOD[] =
        "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"pres:a@b.com\">"
        "<tuple id=\"t1\"><status><basic>open</basic></status></tuple></presence>";
    /* unterminated / malformed tag */
    static const char BAD[] = "<presence><tuple id=\"t1\"><status>";

    pj_pool_t *pool = pool_new("xml");
    pj_xml_node *root;
    char *buf, out[1024];
    int n;

    buf = pj_pool_alloc(pool, sizeof(GOOD));
    pj_memcpy(buf, GOOD, sizeof(GOOD));
    root = pj_xml_parse(pool, buf, sizeof(GOOD) - 1);
    ok("xml.good_parses", root != NULL);
    if (root) {
        n = pj_xml_print(root, out, sizeof(out), PJ_TRUE);
        ok("xml.good_prints", n > 0);
    } else {
        ok("xml.good_prints", 0);
    }

    buf = pj_pool_alloc(pool, sizeof(BAD));
    pj_memcpy(buf, BAD, sizeof(BAD));
    root = pj_xml_parse(pool, buf, sizeof(BAD) - 1);
    ok("xml.bad_rejected", root == NULL);

    pj_pool_release(pool);
}

int main(void)
{
    pj_status_t st;

    st = pj_init();
    if (st != PJ_SUCCESS) { fprintf(stderr, "pj_init failed\n"); return 2; }
    pj_caching_pool_init(&g_cp, &pj_pool_factory_default_policy, 0);
    pj_log_set_level(0);

    st = pjlib_util_init();
    if (st != PJ_SUCCESS) { fprintf(stderr, "pjlib_util_init failed\n"); return 2; }

    /* A SIP endpoint registers the SIP parser modules used by pjsip_parse_msg/uri. */
    st = pjsip_endpt_create(&g_cp.factory, "oracle", &g_endpt);
    if (st != PJ_SUCCESS) { fprintf(stderr, "pjsip_endpt_create failed\n"); return 2; }

    test_sip();
    test_sdp();
    test_stun();
    test_xml();

    pjsip_endpt_destroy(g_endpt);
    pj_caching_pool_destroy(&g_cp);
    pj_shutdown();

    printf("ORACLE_SUMMARY passed=%d failed=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
