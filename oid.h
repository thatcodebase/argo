#pragma once

namespace oid {
    enum {
        iso = 1,
        isombr = 2,
        isombrus = 840,
        isombrus_rsadsi = 113549,
        isombrus_rsadsi_pkcs = 1,
        isombrus_rsadsi_pkcs1 = 1,
        isombrus_rsadsi_pkcs1_rsa = 1,
        isombrus_rsadsi_pkcs1_sha1 = 5,
        isombrus_rsadsi_pkcs5 = 5,
        isombrus_rsadsi_pkcs5_pbkdf2 = 12,
        isombrus_rsadsi_pkcs5_pbes2 = 13,
        isombrus_rsadsi_pkcs9 = 9,
        isombrus_rsadsi_dig = 2,
        isombrus_rsadsi_digmd5 = 5,
        isombrus_rsadsi_enc = 3,
        isombrus_rsadsi_encdes3cbc = 7,
        isoorg = 3,
        isoorgdod = 6,
        isoorgdod_int = 1,
        isoorgdod_intprv = 4,
        isoorgdod_intprv_iana = 1,
        isoorgdod_intprv_ianalan = 4929,
        isoorgdod_intprv_ianalan_alg = 1,
        isoorgdod_intprv_ianalan_alg3des = 7,
        isoorgdod_intprv_ianalan_alg3desofb = 9,
        isoorgdod_intprv_ianalan_alg3descfb = 10,
        isoorgoiw = 14,
        isoorgoiw_sec = 3,
        isoorgoiw_secalg = 2,
        isoorgoiw_secalg_desecb = 6,
        isoorgoiw_secalg_descbc = 7,
        isoorgoiw_secalg_descfb = 9,
        isoorgoiw_secalg_sha1 = 26,
        ccitt = 2,
        ccittds = 5,
        ccittdsat = 4,
        ccittdsat_cn = 3,
        ccittdsat_surname = 4,
        ccittdsat_c = 6,
        ccittdsat_l = 7,
        ccittdsat_s = 8,
        ccittdsat_street = 9,
        ccittdsat_o = 10,
        ccittdsat_ou = 11,
        ccittdsat_t = 12,
        ccittdsat_p = 17,
        ccittdsat_tel = 20,
        ccittdsat_fax = 23,
        ccittdsat_name = 41,
        ccittdsat_email = 200 + 1,
        ccittdsce = 29,
        ccittdsce_subjkey = 14,
        ccittdsce_keyusage = 15,
        ccittdsce_basiccon = 19,
        ccittdsce_authkey = 35,
        ccittco = 16,
        ccittcous = 840,
        ccittcous_org = 1,
        ccittcous_orggov = 101,
        ccittcous_orggovor = 3,
        ccittcous_orggovor_nist = 4,
        ccittcous_orggovor_nistaes = 1,
        ccittcous_orggovor_nistaes_128ecb = 1,
        ccittcous_orggovor_nistaes_128cbc = 2,
        ccittcous_orggovor_nistaes_192ecb = 21,
        ccittcous_orggovor_nistaes_192cbc = 22,
        ccittcous_orggovor_nistaes_256ecb = 41,
        ccittcous_orggovor_nistaes_256cbc = 42,
        ccittcous_orggovor_nisthash = 2,
        ccittcous_orggovor_nisthash_sha256 = 1,
        ccittcous_orggovor_nisthash_sha384 = 2,
        ccittcous_orggovor_nisthash_sha512 = 3,
        ccittcous_orggovor_nisthash_sha224 = 4
    };
}

#define OID_BYTE1(x,y) ((x) * 40 + (y))
#define OID_HIHI(x)    (((x) / 16384 ) | 0x80 )
#define OID_HI(x)      ((((x) % 16384 ) / 128 ) | 0x80 )
#define OID_LO(x)      ((x) % 128 )

#define OID_DESEDECBC  "\x2A\x86\x48\x86\xF7\x0D\x03\x07"
#define OID_PBES2      "\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0D"
#define OID_PBKDF2     "\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C"
#define OID_RSA        "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
