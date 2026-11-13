#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>

// Kerberos/MSV interactive logon packing (ported from the Microsoft credential provider samples).
HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, KERB_INTERACTIVE_UNLOCK_LOGON* pkiul);
HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn, BYTE** prgb, DWORD* pcb);
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);
// Looks up an LSA authentication package id by name ("Negotiate", "Kerberos", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0").
HRESULT RetrieveAuthPackage(const char* name, ULONG* pulAuthPackage);
HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, PWSTR* ppwzProtectedPassword);
HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
HBITMAP CreateTileBitmap();
