#pragma once

#include <stdio.h>

#include <fact/iostream.h>

#include "coap.hpp"
#include <lwip/udp.hpp>
#include <lwip/api.hpp>

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
            // If I put this pkt and the other one on the stack, high speed requests
            // crash the device
            static CoapPacket request;

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

            if ((rc = request.parse(buf, n)) > COAP_ERR)
                printf("Bad packet rc=%d\n", rc);
            else
            {
                size_t buflen = sizeof(buf);
                static CoapPacket response;
#ifdef YACOAP_DEBUG
                request.dump();
#endif
                manager.handleRequest(request, response);

                if ((rc = response.build(buf, &buflen)) > COAP_ERR)
                    printf("coap_build failed rc=%d\n", rc);
                else
                {
    #ifdef YACOAP_DEBUG
                    printf("Sending: ");
                    coap_dump(buf, buflen, true);
                    printf("\n");
    #endif
#ifdef YACOAP_DEBUG
                    response.dump();
#endif

                    lwip::Netbuf nb(buf, buflen);
                    /*
                    auto addr = nbClient.fromAddr();
                    uint16_t port = nbClient.fromPort();
                    clog << "addr: " << *addr << endl;
                    clog << "port: " << port << endl;
                    clog << "buf: " << (void*)buf << "length: " << (uint16_t)buflen << endl;
                    clog << "netbuf_ref result: " << (uint16_t)err << endl; */
                    err_t err = netconn.sendTo(nb, nbClient);

                    clog << "netconn_sendto result: " << (uint16_t)err << endl;

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
