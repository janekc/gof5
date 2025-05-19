//go:build darwin
// +build darwin

package client

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
*/
import "C"
import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// secKeySigner implements crypto.Signer by delegating to SecKeyCreateSignature.
type secKeySigner struct {
	key C.SecKeyRef
	pub crypto.PublicKey
}

func (s *secKeySigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *secKeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var errRef C.CFErrorRef
	var alg C.SecKeyAlgorithm

	switch opts.HashFunc() {
	case crypto.SHA256:
		alg = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
	case crypto.SHA384:
		alg = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
	case crypto.SHA512:
		alg = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
	default:
		return nil, errors.New("unsupported hash function")
	}

	cfDigest := C.CFDataCreate(C.CFAllocatorRef(0), (*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)))
	defer C.CFRelease(C.CFTypeRef(cfDigest))

	errRef = 0
	res := C.SecKeyCreateSignature(s.key, alg, cfDigest, &errRef)
	if res == 0 {
		if errRef != 0 {
			C.CFRelease(C.CFTypeRef(errRef))
		}
		return nil, errors.New("SecKeyCreateSignature failed")
	}
	defer C.CFRelease(C.CFTypeRef(res))

	length := C.CFDataGetLength(C.CFDataRef(res))
	ptr := C.CFDataGetBytePtr(C.CFDataRef(res))
	out := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	return out, nil
}

// loadIdentity loads a certificate and private key from the macOS Keychain by label.
func loadIdentity(label string, kcserial string, kcpathstring string) (tls.Certificate, error) {
	// Build query dictionary
	query := C.CFDictionaryCreateMutable(C.CFAllocatorRef(0), 0, nil, nil)
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassIdentity))
	clabel := C.CString(label)
	cfLabel := C.CFStringCreateWithCString(C.CFAllocatorRef(0), clabel, C.kCFStringEncodingUTF8)
	C.free(unsafe.Pointer(clabel))
	defer C.CFRelease(C.CFTypeRef(cfLabel))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecAttrLabel), unsafe.Pointer(cfLabel))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecReturnRef), unsafe.Pointer(C.kCFBooleanTrue))
	// Instead of kSecMatchLimitOne, get all matches
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitAll))

	var sysKeychain C.SecKeychainRef
	kcPath := C.CString(kcpathstring)
	defer C.free(unsafe.Pointer(kcPath))
	status := C.SecKeychainOpen(kcPath, &sysKeychain)
	if status != C.errSecSuccess {
		return tls.Certificate{}, errors.New("SecKeychainOpen failed")
	}
	defer C.CFRelease(C.CFTypeRef(sysKeychain))

	cfArray := C.CFArrayCreate(
		C.CFAllocatorRef(0),
		(*unsafe.Pointer)(unsafe.Pointer(&sysKeychain)),
		1,
		nil,
	)
	defer C.CFRelease(C.CFTypeRef(cfArray))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecMatchSearchList), unsafe.Pointer(cfArray))

	var result C.CFTypeRef
	status = C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	C.CFRelease(C.CFTypeRef(query))
	if status != C.errSecSuccess {
		return tls.Certificate{}, errors.New("SecItemCopyMatching failed")
	}

	// result is a CFArrayRef of identities
	count := C.CFArrayGetCount((C.CFArrayRef)(result))
	for i := C.CFIndex(0); i < count; i++ {
		identity := (C.SecIdentityRef)(C.CFArrayGetValueAtIndex((C.CFArrayRef)(result), i))
		C.CFRetain(C.CFTypeRef(identity)) // Retain for our use
		defer C.CFRelease(C.CFTypeRef(identity))

		// Extract certificate
		var certRef C.SecCertificateRef
		status = C.SecIdentityCopyCertificate(identity, &certRef)
		if status != C.errSecSuccess {
			continue // skip this one
		}
		defer C.CFRelease(C.CFTypeRef(certRef))

		// Get DER bytes
		derData := C.SecCertificateCopyData(certRef)
		defer C.CFRelease(C.CFTypeRef(derData))
		derLen := C.CFDataGetLength(derData)
		derPtr := C.CFDataGetBytePtr(derData)
		der := C.GoBytes(unsafe.Pointer(derPtr), C.int(derLen))

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		// Print for debug
		fmt.Printf("Found cert: Subject=%s, SerialNumber=%s\n", cert.Subject.String(), cert.SerialNumber.Text(16))

		if cert.SerialNumber.Text(16) == kcserial {
			// Extract private key
			var keyRef C.SecKeyRef
			status = C.SecIdentityCopyPrivateKey(identity, &keyRef)
			if status != C.errSecSuccess {
				continue
			}
			// Do not CFRelease keyRef, as it is managed by the keychain
			signer := &secKeySigner{key: keyRef, pub: cert.PublicKey}
			return tls.Certificate{
				Certificate: [][]byte{der},
				PrivateKey:  signer,
				Leaf:        cert,
			}, nil
		}
	}
	C.CFRelease(result)
	return tls.Certificate{}, errors.New("No matching certificate with desired serial number found")
}
