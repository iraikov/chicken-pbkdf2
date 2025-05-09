;;; pbkdf2.scm - Password-Based Key Derivation Function 1 & 2 as defined in RFC 2898
;;;
;;;
;;; Copyright (C) 2018, Tobias Heilig
;;; All rights reserved.
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;; 1. Redistributions of source code must retain the above copyright
;;;    notice, this list of conditions and the following disclaimer.
;;;
;;; 2. Redistributions in binary form must reproduce the above copyright
;;;    notice, this list of conditions and the following disclaimer in the
;;;    documentation and/or other materials provided with the distribution.
;;;
;;; 3. Neither the name of the authors nor the names of its contributors
;;;    may be used to endorse or promote products derived from this
;;;    software without specific prior written permission.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;; A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;; OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;; SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;; TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;; PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;
;;;
;;; https://tools.ietf.org/html/rfc2898#section-5.1 (PBKDF1)
;;; https://tools.ietf.org/html/rfc2898#section-5.2 (PBKDF2)



(module pbkdf2

        (pbkdf1-md2
         pbkdf1-md5
         pbkdf1-sha1
         pbkdf2-hmac-sha1
         pbkdf2-hmac-sha256
         pbkdf2-hmac-sha384
         pbkdf2-hmac-sha512)


        (import scheme (chicken base)
                (chicken bitwise)
                (chicken blob)
          srfi-1 srfi-4 srfi-13
          message-digest hmac sha2 sha1 md5 md2)


  (define (^ s1 s2)
    (list->string
      (map integer->char
           (map bitwise-xor
                (map char->integer (string->list s1))
                (map char->integer (string->list s2))))))


  (define (pbkdf2 prf hlen s c dklen)

    (define (INT n)
      (list->string
        (map integer->char
             `(,(bitwise-and (arithmetic-shift n -24) #xff)
               ,(bitwise-and (arithmetic-shift n -16) #xff)
               ,(bitwise-and (arithmetic-shift n  -8) #xff)
               ,(bitwise-and n                        #xff)))))

    (define (F i)
      (let ((u1 (prf (string-append s (INT i)))))
        (let loop ((c c) (acc1 u1) (acc2 (prf u1)))
          (if (<= c 1)
              acc1
              (loop (- c 1) (^ acc1 acc2) (prf acc2))))))

    (let ((l (ceiling (/ dklen hlen))))
      (if (> dklen #xffffffff)
          (error "derived key too long")
          (string-take
            (apply string-append (map F (iota l 1)))
            dklen))))


  (define (pbkdf1 hash hlen p s c dklen)
    (if (> dklen hlen)
        (error "derived key too long")
        (let loop ((c c) (acc (hash (string-append p s))))
          (if (<= c 1)
              (string-take acc dklen)
              (loop (- c 1) (hash acc))))))


  (define (get-result-form result-type byte-string)
    (case result-type
      ((string)
        byte-string)
      ((blob)
        (string->blob byte-string))
      ((u8vector)
        (blob->u8vector (string->blob byte-string)))
      ((hex)
        (let* ((hexchars '#("0" "1" "2" "3"
                            "4" "5" "6" "7"
                            "8" "9" "a" "b"
                            "c" "d" "e" "f"))
               (integer->hex (lambda (n)
                               (string-append
                                 (vector-ref hexchars (arithmetic-shift n -4))
                                 (vector-ref hexchars (bitwise-and n #x0f))))))
          (apply string-append (map integer->hex (map char->integer (string->list byte-string))))))
      (else
        (error "unsupported result type"))))


  (define (pbkdf1-md2 password salt count dklen #!optional (result-type 'blob))
    (get-result-form
      result-type
      (pbkdf1 (cut message-digest-string (md2-primitive) <> 'string) 16 password salt count dklen)))

  (define (pbkdf1-md5 password salt count dklen #!optional (result-type 'blob))
    (get-result-form
      result-type
      (pbkdf1 (cut message-digest-string (md5-primitive) <> 'string) 16 password salt count dklen)))


  (define (pbkdf1-sha1 password salt count dklen #!optional (result-type 'blob))
    (get-result-form
      result-type
      (pbkdf1 (cut message-digest-string (sha1-primitive) <> 'string) 20 password salt count dklen)))


  (define (pbkdf2-hmac-sha1 password salt count dklen #!optional (result-type 'blob))
    (get-result-form result-type
      (pbkdf2 (hmac password (sha1-primitive)) 20 salt count dklen)))


  (define (pbkdf2-hmac-sha256 password salt count dklen #!optional (result-type 'blob))
    (get-result-form result-type
      (pbkdf2 (hmac password (sha256-primitive)) 32 salt count dklen)))


  (define (pbkdf2-hmac-sha384 password salt count dklen #!optional (result-type 'blob))
    (get-result-form result-type
      (pbkdf2 (hmac password (sha384-primitive)) 48 salt count dklen)))


  (define (pbkdf2-hmac-sha512 password salt count dklen #!optional (result-type 'blob))
    (get-result-form result-type
      (pbkdf2 (hmac password (sha512-primitive)) 64 salt count dklen)))

)
