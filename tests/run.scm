;;; Password-Based Key Derivation Functions (PBKDF1, PBKDF2)
;;;;
;;;;                    Tests




(import (chicken blob) test pbkdf2)




;; verify Test Vectors as defined in RFC6070
;;
;; for PBKDF2 HMAC SHA1
;;
;; see https://www.ietf.org/rfc/rfc6070.txt

(test-begin "PBKDF2 HMAC SHA1 Test Vectors")


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 1
;;       dkLen = 20
;;
;;     Output:
;;       DK = 0c 60 c8 0f 96 1f 0e 71
;;            f3 a9 b5 24 af 60 12 06
;;            2f e0 37 a6             (20 octets)

(test #${0c60c80f961f0e71f3a9b524af6012062fe037a6}
      (pbkdf2-hmac-sha1 "password" "salt" 1 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 2
;;       dkLen = 20
;;
;;     Output:
;;       DK = ea 6c 01 4d c7 2d 6f 8c
;;            cd 1e d9 2a ce 1d 41 f0
;;            d8 de 89 57             (20 octets)

(test #${ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957}
      (pbkdf2-hmac-sha1 "password" "salt" 2 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 4096
;;       dkLen = 20
;;
;;     Output:
;;       DK = 4b 00 79 01 b7 65 48 9a
;;            be ad 49 d9 26 f7 21 d0
;;            65 a4 29 c1             (20 octets)

(test #${4b007901b765489abead49d926f721d065a429c1}
      (pbkdf2-hmac-sha1 "password" "salt" 4096 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 16777216
;;       dkLen = 20
;;
;;     Output:
;;       DK = ee fe 3d 61 cd 4d a4 e4
;;            e9 94 5b 3d 6b a2 15 8c
;;            26 34 e9 84             (20 octets)

; test case disabled by default because too high
; iteration count results in massive time consumption.
;
#;(test #${eefe3d61cd4da4e4e9945b3d6ba2158c2634e984}
#;      (pbkdf2-hmac-sha1 "password" "salt" 16777216 20))


;;     Input:
;;       P = "passwordPASSWORDpassword" (24 octets)
;;       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
;;       c = 4096
;;       dkLen = 25
;;
;;     Output:
;;       DK = 3d 2e ec 4f e4 1c 84 9b
;;            80 c8 d8 36 62 c0 e4 4a
;;            8b 29 1a 96 4c f2 f0 70
;;            38                      (25 octets)

(test #${3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038}
      (pbkdf2-hmac-sha1 "passwordPASSWORDpassword"
                        "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                        4096
                        25))


;;     Input:
;;       P = "pass\0word" (9 octets)
;;       S = "sa\0lt" (5 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = 56 fa 6a a7 55 48 09 9d
;;            cc 37 d7 f0 34 25 e0 c3 (16 octets)

(test #${56fa6aa75548099dcc37d7f03425e0c3}
      (pbkdf2-hmac-sha1 "pass\x00word" "sa\x00lt" 4096 16))


(test-end "PBKDF2 HMAC SHA1 Test Vectors")




;; verify Test Vectors as defined in RFC6070
;;
;; for PBKDF2 HMAC SHA256
;;
;; see https://www.ietf.org/rfc/rfc6070.txt

(test-begin "PBKDF2 HMAC SHA256 Test Vectors")


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 1
;;       dkLen = 20
;;
;;     Output:
;;       DK = 12 0f b6 cf fc f8 b3 2c
;;            43 e7 22 52 56 c4 f8 37
;;            a8 65 48 c9             (20 octets)

(test #${120fb6cffcf8b32c43e7225256c4f837a86548c9}
      (pbkdf2-hmac-sha256 "password" "salt" 1 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 2
;;       dkLen = 20
;;
;;     Output:
;;       DK = ae 4d 0c 95 af 6b 46 d3
;;            2d 0a df f9 28 f0 6d d0
;;            2a 30 3f 8e             (20 octets)

(test #${ae4d0c95af6b46d32d0adff928f06dd02a303f8e}
      (pbkdf2-hmac-sha256 "password" "salt" 2 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 4096
;;       dkLen = 20
;;
;;     Output:
;;       DK = c5 e4 78 d5 92 88 c8 41
;;            aa 53 0d b6 84 5c 4c 8d
;;            96 28 93 a0             (20 octets)

(test #${c5e478d59288c841aa530db6845c4c8d962893a0}
      (pbkdf2-hmac-sha256 "password" "salt" 4096 20))


;;     Input:
;;       P = "passwordPASSWORDpassword" (24 octets)
;;       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
;;       c = 4096
;;       dkLen = 25
;;
;;     Output:
;;       DK = 34 8c 89 db cb d3 2b 2f
;;            32 d8 14 b8 11 6e 84 cf
;;            2b 17 34 7e bc 18 00 18
;;            1c                      (25 octets)

(test #${348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c}
      (pbkdf2-hmac-sha256 "passwordPASSWORDpassword"
                          "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                          4096
                          25))


;;     Input:
;;       P = "pass\0word" (9 octets)
;;       S = "sa\0lt" (5 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = 89 b6 9d 05 16 f8 29 89
;;            3c 69 62 26 65 0a 86 87 (16 octets)

(test #${89b69d0516f829893c696226650a8687}
      (pbkdf2-hmac-sha256 "pass\x00word" "sa\x00lt" 4096 16))


(test-end "PBKDF2 HMAC SHA256 Test Vectors")




;; verify Test Vectors as defined in RFC6070
;;
;; for PBKDF2 HMAC SHA384
;;
;; see https://www.ietf.org/rfc/rfc6070.txt

(test-begin "PBKDF2 HMAC SHA384 Test Vectors")


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 1
;;       dkLen = 20
;;
;;     Output:
;;       DK = c0 e1 4f 06 e4 9e 32 d7
;;            3f 9f 52 dd f1 d0 c5 c7
;;            19 16 09 23             (20 octets)

(test #${c0e14f06e49e32d73f9f52ddf1d0c5c719160923}
      (pbkdf2-hmac-sha384 "password" "salt" 1 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 2
;;       dkLen = 20
;;
;;     Output:
;;       DK = 54 f7 75 c6 d7 90 f2 19
;;            30 45 91 62 fc 53 5d bf
;;            04 a9 39 18             (20 octets)

(test #${54f775c6d790f21930459162fc535dbf04a93918}
      (pbkdf2-hmac-sha384 "password" "salt" 2 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 4096
;;       dkLen = 20
;;
;;     Output:
;;       DK = 55 97 26 be 38 db 12 5b
;;            c8 5e d7 89 5f 6e 3c f5
;;            74 c7 a0 1c             (20 octets)

(test #${559726be38db125bc85ed7895f6e3cf574c7a01c}
      (pbkdf2-hmac-sha384 "password" "salt" 4096 20))


;;     Input:
;;       P = "passwordPASSWORDpassword" (24 octets)
;;       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
;;       c = 4096
;;       dkLen = 25
;;
;;     Output:
;;       DK = 81 91 43 ad 66 df 9a 55
;;            25 59 b9 e1 31 c5 2a e6
;;            c5 c1 b0 ee d1 8f 4d 28
;;            3b                      (25 octets)

(test #${819143ad66df9a552559b9e131c52ae6c5c1b0eed18f4d283b}
      (pbkdf2-hmac-sha384 "passwordPASSWORDpassword"
                          "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                          4096
                          25))


;;     Input:
;;       P = "pass\0word" (9 octets)
;;       S = "sa\0lt" (5 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = a3 f0 0a c8 65 7e 09 5f
;;            8e 08 23 d2 32 fc 60 b3 (16 octets)

(test #${a3f00ac8657e095f8e0823d232fc60b3}
      (pbkdf2-hmac-sha384 "pass\x00word" "sa\x00lt" 4096 16))


(test-end "PBKDF2 HMAC SHA384 Test Vectors")




;; verify Test Vectors as defined in RFC6070
;;
;; for PBKDF2 HMAC SHA512
;;
;; see https://www.ietf.org/rfc/rfc6070.txt

(test-begin "PBKDF2 HMAC SHA512 Test Vectors")


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 1
;;       dkLen = 20
;;
;;     Output:
;;       DK = 86 7f 70 cf 1a de 02 cf
;;            f3 75 25 99 a3 a5 3d c4
;;            af 34 c7 a6             (20 octets)

(test #${867f70cf1ade02cff3752599a3a53dc4af34c7a6}
      (pbkdf2-hmac-sha512 "password" "salt" 1 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 2
;;       dkLen = 20
;;
;;     Output:
;;       DK = e1 d9 c1 6a a6 81 70 8a
;;            45 f5 c7 c4 e2 15 ce b6
;;            6e 01 1a 2e             (20 octets)

(test #${e1d9c16aa681708a45f5c7c4e215ceb66e011a2e}
      (pbkdf2-hmac-sha512 "password" "salt" 2 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 4096
;;       dkLen = 20
;;
;;     Output:
;;       DK = d1 97 b1 b3 3d b0 14 3e
;;            01 8b 12 f3 d1 d1 47 9e
;;            6c de bd cc             (20 octets)

(test #${d197b1b33db0143e018b12f3d1d1479e6cdebdcc}
      (pbkdf2-hmac-sha512 "password" "salt" 4096 20))


;;     Input:
;;       P = "passwordPASSWORDpassword" (24 octets)
;;       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
;;       c = 4096
;;       dkLen = 25
;;
;;     Output:
;;       DK = 8c 05 11 f4 c6 e5 97 c6
;;            ac 63 15 d8 f0 36 2e 22
;;            5f 3c 50 14 95 ba 23 b8
;;            68                      (25 octets)

(test #${8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868}
      (pbkdf2-hmac-sha512 "passwordPASSWORDpassword"
                          "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                          4096
                          25))


;;     Input:
;;       P = "pass\0word" (9 octets)
;;       S = "sa\0lt" (5 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = 9d 9e 9c 4c d2 1f e4 be
;;            24 d5 b8 24 4c 75 96 65 (16 octets)

(test #${9d9e9c4cd21fe4be24d5b8244c759665}
      (pbkdf2-hmac-sha512 "pass\x00word" "sa\x00lt" 4096 16))


(test-end "PBKDF2 HMAC SHA512 Test Vectors")




;; verify Test Vectors as defined in RFC6070
;;
;; for PBKDF1 MD2
;;
;; see https://www.ietf.org/rfc/rfc6070.txt

(test-begin "PBKDF1 MD2 Test Vectors")


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 1
;;       dkLen = 16
;;
;;     Output:
;;       DK = 38 66 6a 10 b9 f8 cb e4
;;            4c 71 2d 2a 0f de e6 43 (16 octets)

(test #${38666a10b9f8cbe44c712d2a0fdee643}
      (pbkdf1-md2 "password" "salt" 1 16))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 2
;;       dkLen = 16
;;
;;     Output:
;;       DK = 36 ae 3a f3 d4 26 a4 84
;;            2d dc 10 98 b6 bf 67 c5 (16 octets)

(test #${36ae3af3d426a4842ddc1098b6bf67c5}
      (pbkdf1-md2 "password" "salt" 2 16))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = 49 bc 74 34 7a b3 12 ce
;;            f6 0e 8b 88 7f 1c f6 7a (16 octets)

(test #${49bc74347ab312cef60e8b887f1cf67a}
      (pbkdf1-md2 "password" "salt" 4096 16))


;;     Input:
;;       P = "passwordPASSWORDpassword" (24 octets)
;;       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
;;       c = 4096
;;       dkLen = 11
;;
;;     Output:
;;       DK = 30 7b 6b 81 7c 3a d3 8c
;;            84 28 66                (11 octets)

(test #${307b6b817c3ad38c842866}
      (pbkdf1-md2
        "passwordPASSWORDpassword"
        "saltSALTsaltSALTsaltSALTsaltSALTsalt"
        4096
        11))


;;     Input:
;;       P = "pass\0word" (9 octets)
;;       S = "sa\0lt" (5 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = 06 51 96 64 08 c6 90 2c
;;            58 1a c5 76 33 13 09 c2 (16 octets)

(test #${0651966408c6902c581ac576331309c2}
      (pbkdf1-md2 "pass\x00word" "sa\x00lt" 4096 16))


(test-end "PBKDF1 MD2 Test Vectors")




;; verify Test Vectors as defined in RFC6070
;;
;; for PBKDF1 MD5
;;
;; see https://www.ietf.org/rfc/rfc6070.txt

(test-begin "PBKDF1 MD5 Test Vectors")


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 1
;;       dkLen = 16
;;
;;     Output:
;;       DK = b3 05 ca db b3 bc e5 4f
;;            3a a5 9c 64 fe c0 0d ea (16 octets)

(test #${b305cadbb3bce54f3aa59c64fec00dea}
      (pbkdf1-md5 "password" "salt" 1 16))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 2
;;       dkLen = 16
;;
;;     Output:
;;       DK = 5b 6d ad 22 97 82 c6 54
;;            7d 1b 20 d5 66 8e b8 34 (16 octets)

(test #${5b6dad229782c6547d1b20d5668eb834}
      (pbkdf1-md5 "password" "salt" 2 16))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = c8 c1 ea 2f 5e 23 57 44
;;            7a e9 24 47 25 fa ab b9 (16 octets)

(test #${c8c1ea2f5e2357447ae9244725faabb9}
      (pbkdf1-md5 "password" "salt" 4096 16))


;;     Input:
;;       P = "passwordPASSWORDpassword" (24 octets)
;;       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
;;       c = 4096
;;       dkLen = 11
;;
;;     Output:
;;       DK = de 80 62 93 ac b9 04 a2
;;            b6 3d e5                (11 octets)

(test #${de806293acb904a2b63de5}
      (pbkdf1-md5
        "passwordPASSWORDpassword"
        "saltSALTsaltSALTsaltSALTsaltSALTsalt"
        4096
        11))


;;     Input:
;;       P = "pass\0word" (9 octets)
;;       S = "sa\0lt" (5 octets)
;;       c = 4096
;;       dkLen = 16
;;
;;     Output:
;;       DK = 92 1f 9b b3 a3 4d 99 8b
;;            c7 a7 af db 68 48 0b 0b (16 octets)

(test #${921f9bb3a34d998bc7a7afdb68480b0b}
      (pbkdf1-md5 "pass\x00word" "sa\x00lt" 4096 16))


(test-end "PBKDF1 MD5 Test Vectors")




;; verify Test Vectors as defined in RFC6070
;;
;; for PBKDF1 SHA1
;;
;; see https://www.ietf.org/rfc/rfc6070.txt

(test-begin "PBKDF1 SHA1 Test Vectors")


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 1
;;       dkLen = 20
;;
;;     Output:
;;       DK = c8 8e 9c 67 04 1a 74 e0
;;            35 7b ef df f9 3f 87 dd
;;            e0 90 42 14             (20 octets)

(test #${c88e9c67041a74e0357befdff93f87dde0904214}
      (pbkdf1-sha1 "password" "salt" 1 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 2
;;       dkLen = 20
;;
;;     Output:
;;       DK = 47 e9 7e 39 e2 b3 2b 15
;;            eb 92 78 e5 3f 7b fc a5
;;            7f 8e 6b 2c             (20 octets)

(test #${47e97e39e2b32b15eb9278e53f7bfca57f8e6b2c}
      (pbkdf1-sha1 "password" "salt" 2 20))


;;     Input:
;;       P = "password" (8 octets)
;;       S = "salt" (4 octets)
;;       c = 4096
;;       dkLen = 20
;;
;;     Output:
;;       DK = 2d e3 3a d2 13 7e 46 50
;;            ea 29 fb 13 13 6f 96 7b
;;            0a 45 08 d9             (20 octets)

(test #${2de33ad2137e4650ea29fb13136f967b0a4508d9}
      (pbkdf1-sha1 "password" "salt" 4096 20))


;;     Input:
;;       P = "passwordPASSWORDpassword" (24 octets)
;;       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
;;       c = 4096
;;       dkLen = 15
;;
;;     Output:
;;       DK = eb ab f2 ef 03 53 66 7e
;;            55 81 02 1d d8 4b 13    (15 octets)

(test #${ebabf2ef0353667e5581021dd84b13}
      (pbkdf1-sha1
        "passwordPASSWORDpassword"
        "saltSALTsaltSALTsaltSALTsaltSALTsalt"
        4096
        15))


;;     Input:
;;       P = "pass\0word" (9 octets)
;;       S = "sa\0lt" (5 octets)
;;       c = 4096
;;       dkLen = 20
;;
;;     Output:
;;       DK = 2b 66 4b 45 a9 a1 29 db
;;            f2 dc b9 98 98 34 7d b1
;;            35 d8 2f f4             (20 octets)

(test #${2b664b45a9a129dbf2dcb99898347db135d82ff4}
      (pbkdf1-sha1 "pass\x00word" "sa\x00lt" 4096 20))


(test-end "PBKDF1 SHA1 Test Vectors")




;; verify derived key result forms

(test-begin "Result Types")


;; blob implicit

(test #${0c60c80f961f0e71f3a9b524af6012062fe037a6}
      (pbkdf2-hmac-sha1 "password" "salt" 1 20))


;; blob explicit

(test #${0c60c80f961f0e71f3a9b524af6012062fe037a6}
      (pbkdf2-hmac-sha1 "password" "salt" 1 20 'blob))


;; hex

(test "0c60c80f961f0e71f3a9b524af6012062fe037a6"
      (pbkdf2-hmac-sha1 "password" "salt" 1 20 'hex))


;; string

(test #${0c60c80f961f0e71f3a9b524af6012062fe037a6}
      (string->blob (pbkdf2-hmac-sha1 "password" "salt" 1 20 'string)))


;; u8vector

(test #u8( 12 96 200  15 150
           31 14 113 243 169
          181 36 175  96  18
            6 47 224  55 166)
      (pbkdf2-hmac-sha1 "password" "salt" 1 20 'u8vector))


(test-end "Result Types")




;; verify invalid input

(test-begin "PBKDF2 Invalid Input")


;; error derived key too long

(test-error "derived key too long"
            (pbkdf2-hmac-sha1 "password" "salt" 1 (expt 2 32)))


;; error unsupported result type

(test-error "unsupported result type"
            (pbkdf2-hmac-sha1 "password" "salt" 1 20 'foo))


(test-end "PBKDF2 Invalid Input")




;; verify invalid input

(test-begin "PBKDF1 Invalid Input")


;; error derived key too long

(test-error "derived key too long"
            (pbkdf1-md5 "password" "salt" 1 17))

(test-error "derived key too long"
            (pbkdf1-sha1 "password" "salt" 1 21))

;; error unsupported result type

(test-error "unsupported result type"
            (pbkdf1-md5 "password" "salt" 1 20 'foo))


(test-end "PBKDF1 Invalid Input")




(test-exit)


