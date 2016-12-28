// C++ wrappers/helpers for YaCoAP

#pragma once

extern "C" {
#include "coap.h"

// NOTE: only used for packet dump debug facility.  If this causes any problems or
// bloat, we need to move it out of here
#include "coap_dump.h"
}


namespace yacoap {

inline coap_state_t coap_make_content_response(
    const coap_packet_t* inpkt,
    const uint8_t* content_type,
    const uint8_t* content,
    const size_t content_len,
    coap_packet_t* pkt)
{
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
        COAP_TYPE_ACK, COAP_RSPCODE_CONTENT,
        content_type,
        content,
        content_len,
        pkt);
}


inline coap_state_t coap_make_content_response(
    const coap_packet_t* inpkt,
    const coap_resource_t* res,
    const uint8_t* content,
    const size_t content_len,
    coap_packet_t* pkt)
{
    return coap_make_content_response(inpkt,
        res->content_type,
        content,
        content_len,
        pkt);
}


// TODO: Test this, not yet tested
inline coap_state_t coap_make_badrequest_response(const coap_packet_t* inpkt, coap_packet_t* pkt)
{
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
        COAP_TYPE_ACK, COAP_RSPCODE_BAD_REQUEST,
        NULL, NULL, 0,
        pkt);
}

// TODO: since coap_packet_t is used by callbacks all over the place,
// it makes more sense to use overloaded functions rather than this
// helper class
class CoapPacket
{
    coap_packet_t packet;

public:
    coap_state_t makeResponse(coap_packet_t* inpkt,
        const coap_msgtype_t msgtype,
        const coap_responsecode_t rspcode,
        const uint8_t *content_type,
        const uint8_t *content,
        const size_t content_len)
    {
        return coap_make_response(inpkt->hdr.id, &inpkt->tok,
            msgtype,
            rspcode,
            content_type,
            content,
            content_len,
            &packet);
    }

    coap_state_t makeContentResponse(CoapPacket& request,
        const uint8_t *content_type,
        const uint8_t *content,
        const size_t content_len)
    {
        return makeResponse(&request.packet,
            COAP_TYPE_ACK, COAP_RSPCODE_CONTENT,
            content_type,
            content,
            content_len);
    }


    coap_state_t build(uint8_t* buf, size_t* buflen)
    {
        return coap_build(&packet, buf, buflen);
    }

    coap_state_t parse(const uint8_t *buf, const size_t buflen)
    {
        return coap_parse(buf, buflen, &packet);
    }

#if YACOAP_DEBUG
    void dump()
    {
        coap_dump_packet(&packet);
    }
#endif

    operator coap_packet_t&()
    {
        return packet;
    }
};

// Like a server, but only the resource component - the request/response
// has to be initiated from outside (thus staying platform-independent in
// regards to networking)
template <const coap_resource_t* resources, size_t rsplen = 128>
class CoapManager
{
    // response buffer.  Response packaet content is built and placed here
    // this specifically serves the "well known" request
    char rsp[rsplen];

public:
    CoapManager()
    {
        coap_make_link_format(resources, rsp, rsplen);
    }

    coap_state_t handleRequest(
        const coap_packet_t *inpkt,
        coap_packet_t *pkt)
    {
        // a little hack-ey but pretty sure resources really are a const
        return coap_handle_request((coap_resource_t*)resources, inpkt, pkt);
    }


    coap_state_t handleRequest(
        CoapPacket& inpkt,
        CoapPacket& pkt)
    {
        // a little hack-ey but pretty sure resources really are a const
        return coap_handle_request((coap_resource_t*)resources,
            &((coap_packet_t&)inpkt),
            &((coap_packet_t&)pkt));
    }


    coap_state_t handleResponse(
        const coap_packet_t *reqpkt,
        coap_packet_t *rsppkt
    )
    {
        return coap_handle_response(resources, reqpkt, rsppkt);
    }

    int handle_get_well_known_core(const coap_resource_t *resource,
                                          const coap_packet_t *inpkt,
                                          coap_packet_t *pkt)
    {
        return coap_make_content_response(inpkt, resource,
            (const uint8_t*)rsp, strlen(rsp), pkt);
    }

/*
    static int _handle_get_well_known_core(const coap_resource_t *resource,
                                          const coap_packet_t *inpkt,
                                          coap_packet_t *pkt)
    {
        return handle_get_well_known_core(resource, inpkt, pkt);
    } */
};


}

extern const coap_resource_path_t path_well_known_core; // = {2, {".well-known", "core"}};


#define COAP_RESOURCE_WELLKNOWN(func_handle_get_well_known_core)    \
{COAP_RDY, COAP_METHOD_GET, COAP_TYPE_ACK,                          \
    func_handle_get_well_known_core, &path_well_known_core,         \
    COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_APP_LINKFORMAT)}
#define COAP_RESOURCE_NULL                                          \
{(coap_state_t)0, (coap_method_t)0, (coap_msgtype_t)0,              \
    NULL, NULL,                                                     \
    COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_NONE)}
#define COAP_RESOURCE_GET(func_handle_get, path_get, content_type)            \
{COAP_RDY, COAP_METHOD_GET, COAP_TYPE_ACK,                          \
    func_handle_get, path_get,                                      \
    COAP_SET_CONTENTTYPE(content_type)}
// TODO: PUT macro still untested
#define COAP_RESOURCE_PUT(func_handle_get, path_put, content_type)            \
{COAP_RDY, COAP_METHOD_GET, COAP_TYPE_ACK,                          \
    func_handle_put, path_put,                                      \
    COAP_SET_CONTENTTYPE(content_type)}
