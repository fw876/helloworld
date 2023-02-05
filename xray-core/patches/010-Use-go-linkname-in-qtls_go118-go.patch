From 00c95761189162504ebc2c0df3266e9395c7e40d Mon Sep 17 00:00:00 2001
From: RPRX <63339210+RPRX@users.noreply.github.com>
Date: Sat, 4 Feb 2023 21:27:13 +0800
Subject: [PATCH] Use go:linkname in qtls_go118.go

Once and for all, whatever
---
 common/protocol/quic/qtls_go118.go | 20 +++++++++++---------
 go.mod                             |  2 +-
 2 files changed, 12 insertions(+), 10 deletions(-)

--- a/common/protocol/quic/qtls_go118.go
+++ b/common/protocol/quic/qtls_go118.go
@@ -1,16 +1,18 @@
 package quic
 
 import (
+	"crypto"
 	"crypto/cipher"
-
-	"github.com/quic-go/qtls-go1-20"
-)
-
-type (
-	// A CipherSuiteTLS13 is a cipher suite for TLS 1.3
-	CipherSuiteTLS13 = qtls.CipherSuiteTLS13
+	_ "crypto/tls"
+	_ "unsafe"
 )
 
-func AEADAESGCMTLS13(key, fixedNonce []byte) cipher.AEAD {
-	return qtls.AEADAESGCMTLS13(key, fixedNonce)
+type CipherSuiteTLS13 struct {
+	ID     uint16
+	KeyLen int
+	AEAD   func(key, fixedNonce []byte) cipher.AEAD
+	Hash   crypto.Hash
 }
+
+//go:linkname AEADAESGCMTLS13 crypto/tls.aeadAESGCMTLS13
+func AEADAESGCMTLS13(key, nonceMask []byte) cipher.AEAD
--- a/go.mod
+++ b/go.mod
@@ -11,7 +11,6 @@ require (
 	github.com/miekg/dns v1.1.50
 	github.com/pelletier/go-toml v1.9.5
 	github.com/pires/go-proxyproto v0.6.2
-	github.com/quic-go/qtls-go1-20 v0.1.0
 	github.com/quic-go/quic-go v0.32.0
 	github.com/refraction-networking/utls v1.2.0
 	github.com/sagernet/sing v0.1.6
@@ -46,6 +45,7 @@ require (
 	github.com/pmezard/go-difflib v1.0.0 // indirect
 	github.com/quic-go/qtls-go1-18 v0.2.0 // indirect
 	github.com/quic-go/qtls-go1-19 v0.2.0 // indirect
+	github.com/quic-go/qtls-go1-20 v0.1.0 // indirect
 	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
 	go.uber.org/atomic v1.10.0 // indirect
 	golang.org/x/exp v0.0.0-20230131160201-f062dba9d201 // indirect
