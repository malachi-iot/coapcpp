#pragma once

#include <stdio.h>

#include <fact/iostream.h>

#include "coap.hpp"
#include <lwip/udp.hpp>
#include <lwip/api.hpp>

#ifndef ASSERT
#define ASSERT(condition, message)
#endif

namespace yacoap
{
    using namespace FactUtilEmbedded::std;
    
    //static uint8_t buf[1024]

    template <const coap_resource_t* resources, size_t rsplen = 128>
    class CoapServer
        // really want it an "is-a" but the handleRequest call gets an error that
        // I can't yet figure out
        //: public CoapManager<resources,rsplen>

    {
        CoapManager<resources, rsplen> manager;
        uint8_t buf[1024];

    public:
        int handle_get_well_known_core(const coap_resource_t *resource,
                                              const coap_packet_t *inpkt,
                                              coap_packet_t *pkt)
        {
            return manager.handle_get_well_known_core(resource, inpkt, pkt);
        }
        
        // this is a BLOCKING handler, designed for an RTOS
        void handler()
        {
            clog << "Waiting..." << endl;

            lwip::Netconn netconn(NETCONN_UDP);
            
            if(!netconn.isAllocated())
            {
                cerr << "Failed to allocate socket";
                abort();
            }

            netconn.bind(IP_ADDR_ANY, COAP_DEFAULT_PORT);
            netconn.set_recvtimeout(0); // blocking
            //cout << "Waiting...1" << endl;

            clog << "Waiting...1" << endl;
            lwip::Netbuf nbClient(false);
            netconn.recv(nbClient);

            handler(netconn, nbClient);

            clog << "Finishing up 1" << endl;

            nbClient.del();

            clog << "Finishing up 2" << endl;

            netconn.disconnect();
            netconn.del();
        }

        // Less-blocking one (sendTo I believe still blocks),
        // netconn has already received its payload into nbClient
        void handler(lwip::Netconn& netconn, lwip::Netbuf& nbClient)
        {
            int n, rc;
            //CoapPacket request;

            //TODO: operate directly on buffer
            u16_t copied_len = nbClient.copy(buf, sizeof(buf));
            n = copied_len;
            /* zero-copy mode.  Not ready yet but testing suggests
               that datagram copy() vs data() size are the same , however I wouldn't 
               count on that cross platform */
            /*
            void* chainBuf;
            u16_t chainLen;
            nbClient.data(&chainBuf, &chainLen);
            n = nbClient.len();
            //uint8_t* buf = (uint8_t*)chainBuf; // not ready for primetime due to response building
            */
            
            /*
            cout << "Chain len: " << (uint16_t) chainLen << endl;
            cout << "Copied len: " << (uint16_t) copied_len << endl;
            cout << "calc len: " << (uint16_t) n << endl; */

#ifdef YACOAP_DEBUG
            printf("Received: ");
            coap_dump(buf, n, true);
            printf("\n");
#endif

            // this parses the buffer
            CoapRequest request(buf, n);

            if (request.getResult() > COAP_ERR)
                clog << "Bad packet rc=" << request.getResult() << endl;
            else
            {
                size_t buflen = sizeof(buf);
                CoapPacket response;
#ifdef YACOAP_DEBUG
                request.dump();
#endif

                manager.handleRequest(request, response);

                if ((rc = response.build(buf, &buflen)) > COAP_ERR)
                    printf("coap_build failed rc=%d\n", rc);
                else
                {
    #ifdef YACOAP_DEBUG
                    clog << "Sending: " << (uint16_t) buflen << endl;
                    coap_dump(buf, buflen, true);
                    clog << endl;
    #endif
#ifdef YACOAP_DEBUG
                    response.dump();
#endif

#ifdef DEBUG_REF
                    // love the zero-copy ref, but I can't get it to work reliably
                    // I can't issue free/delete on it and memory corruption occurs
                    // when using it + sendto
                    lwip::Netbuf nb(buf, buflen);
#else
                    lwip::Netbuf nb;
                    
                    void* newbuf = nb.alloc(buflen);
                    
                    memcpy(newbuf, buf, buflen);
#endif

                    manager.rspDiagnostic();

                    /*
                    auto addr = nbClient.fromAddr();
                    uint16_t port = nbClient.fromPort();
                    clog << "addr: " << *addr << endl;
                    clog << "port: " << port << endl;
                    clog << "buf: " << (void*)buf << "length: " << (uint16_t)buflen << endl;
                    clog << "netbuf_ref result: " << (uint16_t)err << endl; */
#ifdef DEBUG
                    netbuf* _netbuf_to = nbClient;
                    netbuf* _netbuf_from = nb;
                    
                    err_t err = netconn_sendto(netconn, _netbuf_from,
                        netbuf_fromaddr(_netbuf_to), netbuf_fromport(_netbuf_to));
#else
                    err_t err = netconn.sendTo(nb, nbClient);
#endif
                    manager.rspDiagnostic();

                    ASSERT(err == 0, "netconn send error: " << err);
                    
                    //clog << "netconn_sendto result: " << (uint16_t)err << endl;

#ifndef DEBUG_REF
                    nb.del();
#endif
                    //nb.free();
                    // This delete operation crashes it... not sure why
                    //netbuf_delete(_nb2);
                    // not well documented, but seems that ref bufs you call FREE instead
                    // of delete...
                    //cout << "_nb2: " << (void*)_nb2 << endl;
                    //netbuf_free(_nb2);
                }
            }
        }
    };
}
