#pragma once

#include <stdio.h>

#include <fact/iostream.h>

#include "coap.hpp"
#include <lwip/udp.hpp>
#include <lwip/api.hpp>

namespace yacoap
{
    using namespace FactUtilEmbedded::std;

    template <const coap_resource_t* resources, size_t rsplen = 128>
    class CoapServer
        // really want it an "is-a" but the handleRequest call gets an error that
        // I can't yet figure out
        //: public CoapManager<resources,rsplen>

    {
        CoapManager<resources, rsplen> manager;
        uint8_t buf[1024];

    public:
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
            static yacoap::CoapPacket _pkt;

            //TODO: operate directly on buffer
            u16_t copied_len = nbClient.copy(buf, sizeof(buf));
            void* chainBuf;
            u16_t chainLen;
            nbClient.data(&chainBuf, &chainLen);
            n = nbClient.len();

            /*
            cout << "Chain len: " << (uint16_t) chainLen << endl;
            cout << "Copied len: " << (uint16_t) copied_len << endl;
            cout << "calc len: " << (uint16_t) n << endl; */

#ifdef YACOAP_DEBUG
            printf("Received: ");
            coap_dump(buf, n, true);
            printf("\n");
#endif

            if ((rc = _pkt.parse(buf, n)) > COAP_ERR)
                printf("Bad packet rc=%d\n", rc);
            else
            {
                size_t buflen = sizeof(buf);
                static yacoap::CoapPacket _rsppkt;
#ifdef YACOAP_DEBUG
                _pkt.dump();
#endif
                manager.handleRequest(_pkt, _rsppkt);

                if ((rc = _rsppkt.build(buf, &buflen)) > COAP_ERR)
                    printf("coap_build failed rc=%d\n", rc);
                else
                {
    #ifdef YACOAP_DEBUG
                    printf("Sending: ");
                    coap_dump(buf, buflen, true);
                    printf("\n");
    #endif
#ifdef YACOAP_DEBUG
                    _rsppkt.dump();
#endif

                    lwip::Netbuf nb(buf, buflen);
                    //netbuf* _nb2 = netbuf_new();
                    auto addr = nbClient.fromAddr();
                    uint16_t port = nbClient.fromPort();
                    /*
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
