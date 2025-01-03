from ikev2_class import EpdgIKEv2

TEST_CONFIG = {
    "SUPPORT_ENC_NULL_DH_768MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL, # encryption algorithms
                EpdgIKEv2.PRF_SHA1, # pseudo-random functions
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5, 
                EpdgIKEv2.INT_SHA1_96, # (integrity) hashing algorithm
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_768MODP, # diffie-hellman key exchange
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_768MODP,
    },
    "SUPPORT_ENC_NULL_DH_1024MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_ENC_NULL_DH_2048MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
    },
    "SUPPORT_DH_768MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_768MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_768MODP,
    },
    "SUPPORT_DH_1024MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_DH_1536MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1536MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1536MODP,
    },
    "SUPPORT_DH_2048MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
    },
    "SUPPORT_DH_3072MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_3072MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_3072MODP,
    },
    "SUPPORT_DH_4096MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_4096MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_4096MODP,
    },
    "SUPPORT_DH_6144MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_6144MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_6144MODP,
    },
    "SUPPORT_DH_8192MODP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_8192MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_8192MODP,
    },
    "SUPPORT_DH_256ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_256ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_256ECP,
    },
    "SUPPORT_DH_384ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_384ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_384ECP,
    },
    "SUPPORT_DH_512ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_512ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_512ECP,
    },
    "SUPPORT_DH_192ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_192ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_192ECP,
    },
    "SUPPORT_DH_224ECP": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_224ECP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_224ECP,
    },
    "SUPPORT_DH_X25519": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_X25519,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_X25519,
    },
    "TOLERATE_DH1024": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
                EpdgIKEv2.DH_768MODP,
                EpdgIKEv2.DH_1536MODP,
                EpdgIKEv2.DH_2048MODP,
                EpdgIKEv2.DH_3072MODP,
                EpdgIKEv2.DH_4096MODP,
                EpdgIKEv2.DH_6144MODP,
                EpdgIKEv2.DH_8192MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "DOWNGRADE_DH2048": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
                EpdgIKEv2.DH_768MODP,
                EpdgIKEv2.DH_1024MODP,
                EpdgIKEv2.DH_1536MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
    },
    "CHECK_AUTOCONF_DOMAINS": {},
    # encryption and integrity scan:
    "SUPPORT_IKE_ENCR_NULL": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_NULL,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_IKE_WEAK_INT": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_AES_128,
                EpdgIKEv2.ENC_AES_256,
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_IKE_ENCR_DES": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_IKE_ENCR_3DES": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_1024MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_1024MODP,
    },
    "SUPPORT_IKE_ENCR_3DES_DH_2048": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_2048MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_2048MODP,
    },
    "SUPPORT_IKE_ENCR_3DES_DH_3072": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_3072MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_3072MODP,
    },
    "SUPPORT_IKE_ENCR_3DES_DH_4096": {
        "sa_list": [
            [
                EpdgIKEv2.ENC_3DES,
                EpdgIKEv2.PRF_SHA1,
                EpdgIKEv2.PRF_SHA2_256,
                EpdgIKEv2.PRF_MD5,
                EpdgIKEv2.INT_SHA1_96,
                EpdgIKEv2.INT_SHA2_256_128,
                EpdgIKEv2.INT_MD5_96,
                EpdgIKEv2.DH_4096MODP,
            ]
        ],
        "key_echange": EpdgIKEv2.KE_DH_4096MODP,
    },
}