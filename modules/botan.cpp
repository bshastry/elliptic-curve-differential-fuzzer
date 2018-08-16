// Copyright (c) 2018 Catena cyber
// Author Philippe Antoine <p.antoine@catenacyber.fr>


#include "../fuzz_ec.h"
#include <botan/ecdsa.h>
#include <botan/oids.h>

#define BYTECEIL(numbits) (((numbits) + 7) >> 3)

static const Botan::OIDS eccurvetypeFromTlsId(uint16_t tlsid) {
    switch (tlsid) {
        case 18:
            return Botan::OIDS::lookup("secp192k1");
        case 19:
            return Botan::OIDS::lookup("secp192r1");
        case 20:
            return Botan::OIDS::lookup("secp224k1");
        case 21:
            return Botan::OIDS::lookup("secp224r1");
        case 22:
            return Botan::OIDS::lookup("secp256k1");
        case 23:
            return Botan::OIDS::lookup("secp256r1");
        case 24:
            return Botan::OIDS::lookup("secp384r1");
        case 25:
            return Botan::OIDS::lookup("secp521r1");
        case 26:
            return Botan::OIDS::lookup("brainpool256r1");
        case 27:
            return Botan::OIDS::lookup("brainpool384r1");
        case 28:
            return Botan::OIDS::lookup("brainpool512r1");
    }
    return NULL;
}

static void botan_to_ecfuzzer(Botan::PointGFp pointZ, fuzzec_output_t * output, size_t index, size_t byteLen) {
    if (pointZ.is_zero()) {
        output->pointSizes[index] = 1;
        output->points[index][0] = 0;
    } else {
        output->pointSizes[index] = 1 + 2 * byteLen;
        pointZ.get_affine_x(output->points[index]+1).binary_encode();
        pointZ.get_affine_y(output->points[index]+1+byteLen).binary_encode();
    }
}

extern "C" void fuzzec_botan_process(fuzzec_input_t * input, fuzzec_output_t * output) {

    //initialize
    const Botan::OIDS oid = eccurvetypeFromTlsId(input->tls_id);
    if (oid == NULL) {
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED;
        return;
    }
    Botan::EC_Group group(oid);
    Botan::BigInt scalar1(input->bignum1, input->bignum1Size);
    Botan::BigInt scalar2(input->bignum2, input->bignum2Size);

    //elliptic curve computations
    //P1=scalar1*G
    Botan::PointGFp point1 = group.get_base_point() * scalar1;
    //P2=scalar2*P1 (=scalar2*scalar1*G)
    Botan::PointGFp point2 = point1 * scalar1;
    //P3=P1+P2
    Botan::PointGFp point3 = point1 + point2;

    //format output
    botan_to_ecfuzzer(point1, output, 0, BYTECEIL(input->groupBitLen));
    botan_to_ecfuzzer(point2, output, 1, BYTECEIL(input->groupBitLen));
    botan_to_ecfuzzer(point3, output, 2, BYTECEIL(input->groupBitLen));

#ifdef DEBUG
    printf("botan:");
    for (size_t j=0; j<FUZZEC_NBPOINTS; j++) {
        for (size_t i=0; i<output->pointSizes[j]; i++) {
            printf("%02x", output->points[j][i]);
        }
        printf("\n");
    }
#endif
    output->errorCode = FUZZEC_ERROR_NONE;

    return;
}
