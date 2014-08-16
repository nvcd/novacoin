// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"
#include "script.h"
#include "base58.h"

extern bool fWalletUnlockMintOnly;

bool CKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key))
        return false;
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::AddKey(const CKey& key)
{
    bool fCompressed = false;
    CSecret secret = key.GetSecret(fCompressed);
    {
        LOCK(cs_KeyStore);
        mapKeys[key.GetPubKey().GetID()] = make_pair(secret, fCompressed);
    }
    return true;
}

bool CBasicKeyStore::AddKeyPair(const CMutableKey& keyPair)
{
    CSecret L, H;
    keyPair.GetSecrets(L, H);
    {
        LOCK(cs_KeyStore);
        mapKeyPairs[keyPair.GetID()] = make_pair(keyPair.GetMutablePubKey().GetH(), make_pair(L, H));
    }
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    {
        LOCK(cs_KeyStore);
        mapScripts[redeemScript.GetID()] = redeemScript;
    }
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    bool result;
    {
        LOCK(cs_KeyStore);
        result = (mapScripts.count(hash) > 0);
    }
    return result;
}


bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    {
        LOCK(cs_KeyStore);
        ScriptMap::const_iterator mi = mapScripts.find(hash);
        if (mi != mapScripts.end())
        {
            redeemScriptOut = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);

    CTxDestination address;
    if (ExtractDestination(dest, address)) {
        CKeyID keyID;
        CBitcoinAddress(address).GetKeyID(keyID);
        if (HaveKey(keyID))
            return false;
    }

    setWatchOnly.insert(dest);
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CCryptoKeyStore::SetCrypted()
{
    {
        LOCK(cs_KeyStore);
        if (fUseCrypto)
            return true;
        if (!mapKeys.empty())
            return false;
        if (!mapKeyPairs.empty())
            return false;
        fUseCrypto = true;
    }
    return true;
}

bool CCryptoKeyStore::Lock()
{
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
        fWalletUnlockMintOnly = false;
    }

    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if(!DecryptSecret(vMasterKeyIn, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
                return false;
            if (vchSecret.size() != 32)
                return false;
            CKey key;
            key.SetPubKey(vchPubKey);
            key.SetSecret(vchSecret);
            if (key.GetPubKey() == vchPubKey)
                break;
            return false;
        }

        CryptedKeyPairMap::const_iterator mip = mapCryptedKeyPairs.begin();
        for (; mip != mapCryptedKeyPairs.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mip).second.first.second;
            const std::vector<unsigned char> &vchCryptedSecret = (*mip).second.second;
            CSecret vchSecret;
            if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
                return false;
            if (vchSecret.size() != 32)
                return false;
            CKey key;
            key.SetPubKey(vchPubKey);
            key.SetSecret(vchSecret);
            if (key.GetPubKey() == vchPubKey)
                break;
            return false;
        }

        vMasterKey = vMasterKeyIn;
    }
    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::AddKey(const CKey& key)
{
    {
        LOCK(cs_KeyStore);

        CScript script;
        script.SetDestination(key.GetPubKey().GetID());

        if (HaveWatchOnly(script))
            return false;

        if (!IsCrypted())
            return CBasicKeyStore::AddKey(key);

        if (IsLocked())
            return false;

        std::vector<unsigned char> vchCryptedSecret;
        CPubKey vchPubKey = key.GetPubKey();
        bool fCompressed;
        if (!EncryptSecret(vMasterKey, key.GetSecret(fCompressed), vchPubKey.GetHash(), vchCryptedSecret))
            return false;

        if (!AddCryptedKey(key.GetPubKey(), vchCryptedSecret))
            return false;
    }
    return true;
}


bool CCryptoKeyStore::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    }
    return true;
}

bool CCryptoKeyStore::AddCryptedKeyPair(const uint256 &keyPairID, const CSecret &secretL, const CPubKey &vchPubKeyH, const std::vector<unsigned char> &vchCryptedSecretH)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        mapCryptedKeyPairs[keyPairID] = make_pair(make_pair(secretL, vchPubKeyH), vchCryptedSecretH);
    }
    return true;
}

bool CCryptoKeyStore::AddKeyPair(const CMutableKey& keyPair)
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::AddKeyPair(keyPair);

        if (IsLocked())
            return false;

        std::vector<unsigned char> vchCryptedSecretH;
        CSecret vchSecretL, vchSecretH;
        keyPair.GetSecrets(vchSecretL, vchSecretH);
        CPubKey vchPubKeyH = keyPair.GetMutablePubKey().GetH();

        if (!EncryptSecret(vMasterKey, vchSecretH, vchPubKeyH.GetHash(), vchCryptedSecretH))
            return false;

        if (!AddCryptedKeyPair(keyPair.GetID(), vchSecretL, vchPubKeyH, vchCryptedSecretH))
            return false;
    }
    return true;
}


bool CCryptoKeyStore::GetKey(const CKeyID &address, CKey& keyOut) const
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::GetKey(address, keyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end())
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
                return false;
            if (vchSecret.size() != 32)
                return false;
            keyOut.SetPubKey(vchPubKey);
            keyOut.SetSecret(vchSecret);
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::GetKeyPair(const uint256 &keyPairID, CMutableKey& keyPairOut) const
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::GetKeyPair(keyPairID, keyPairOut);
        CryptedKeyPairMap::const_iterator mi = mapCryptedKeyPairs.find(keyPairID);
        if (mi != mapCryptedKeyPairs.end())
        {
            const CPubKey &vchPubKey = (*mi).second.first.second;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CSecret vchSecret;
            if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
                return false;
            if (vchSecret.size() != 32)
                return false;
            keyPairOut.Reset();
            keyPairOut.SetSecrets((*mi).second.first.first, vchSecret);
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CKeyStore::GetPubKey(address, vchPubKeyOut);
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end())
        {
            vchPubKeyOut = (*mi).second.first;
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::EncryptKeys(CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK(cs_KeyStore);
        if (!mapCryptedKeys.empty() || IsCrypted())
            return false;

        fUseCrypto = true;
        BOOST_FOREACH(KeyMap::value_type& mKey, mapKeys)
        {
            CKey key;
            if (!key.SetSecret(mKey.second.first, mKey.second.second))
                return false;
            const CPubKey vchPubKey = key.GetPubKey();
            std::vector<unsigned char> vchCryptedSecret;
            bool fCompressed;
            if (!EncryptSecret(vMasterKeyIn, key.GetSecret(fCompressed), vchPubKey.GetHash(), vchCryptedSecret))
                return false;
            if (!AddCryptedKey(vchPubKey, vchCryptedSecret))
                return false;
        }
        mapKeys.clear();

        BOOST_FOREACH(KeyPairMap::value_type& mKey, mapKeyPairs)
        {
            CMutableKey keyPair;
            if (!keyPair.SetSecrets(mKey.second.second.first, mKey.second.second.second))
                return false;

            const CPubKey vchPubKeyH = mKey.second.first;
            std::vector<unsigned char> vchCryptedSecretH;
            if (!EncryptSecret(vMasterKeyIn, mKey.second.second.second, vchPubKeyH.GetHash(), vchCryptedSecretH))
                return false;
            if (!AddCryptedKeyPair(keyPair.GetID(), mKey.second.second.first, vchPubKeyH, vchCryptedSecretH))
                return false;
        }
        mapKeyPairs.clear();
    }
    return true;
}
