// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include "crypter.h"
#include "sync.h"
#include <boost/signals2/signal.hpp>
#include <boost/variant.hpp>
#include <boost/foreach.hpp>

class CScript;

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

/** A txout script template with a specific destination. It is either:
  * CNoDestination: no destination set
  * CKeyID: TX_PUBKEYHASH destination
  * CScriptID: TX_SCRIPTHASH destination
  *
  * A CTxDestination is the internal data type encoded in a CBitcoinAddress.
  */
typedef boost::variant<CNoDestination, CKeyID, CScriptID> CTxDestination;

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {}

    // Add a key to the store.
    virtual bool AddKey(const CKey& key) =0;

    // Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    // Support for BIP 0013 : see https://en.bitcoin.it/wiki/BIP_0013
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    // Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) =0;
    virtual bool HaveWatchOnly(const CScript &dest) const =0;

    virtual bool GetSecret(const CKeyID &address, CSecret& vchSecret, bool &fCompressed) const
    {
        CKey key;
        if (!GetKey(address, key))
            return false;
        vchSecret = key.GetSecret(fCompressed);
        return true;
    }

    // Add a key pair to the store.
    virtual bool AddKeyPair(const CMutableKey& keypair) =0;

    // Check whether a key pair corresponding to a given public key pair is present in the store.
    virtual bool HaveKeyPair(const uint256 &pairID) const =0;

    // Get private keypair correcponding to provided pubkey pair
    virtual bool GetKeyPair(const uint256 &pairID, CMutableKey &keypair) const =0;

    // Check whether a key pair corresponding to a given (R, variant)
    virtual bool HaveKeyPair(const CPubKey &R, const CPubKey &vchPubKeyVariant, uint256 &pairID) const =0;

    // Calculate private key corresponding to a given (R, variant) amd pair ID
    virtual bool GetOneTimeKey(const CPubKey &R, const CPubKey &vchPubKeyVariant, CKey &oneTimeKeyOut, uint256 pairID) const =0;
};

// keypair map
// storing vchPubKeyH, it's used in HaveKeyPair method
typedef std::pair<uint256, std::pair<CPubKey, std::pair<CSecret, CSecret> > > KeyPair;
typedef std::map<uint256, std::pair<CPubKey, std::pair<CSecret, CSecret> > > KeyPairMap;

typedef std::map<CKeyID, std::pair<CSecret, bool> > KeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::set<CScript> WatchOnlySet;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;
    KeyPairMap mapKeyPairs;
    ScriptMap mapScripts;
    WatchOnlySet setWatchOnly;

public:
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut.Reset();
                keyOut.SetSecret((*mi).second.first, (*mi).second.second);
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;

    virtual bool AddWatchOnly(const CScript &dest);
    virtual bool HaveWatchOnly(const CScript &dest) const;

    bool AddKeyPair(const CMutableKey& keypair);
    bool HaveKeyPair(const uint256 &pairID) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeyPairs.count(pairID) > 0);
        }
        return result;
    }
    bool GetKeyPair(const uint256 &pairID, CMutableKey &keypair) const
    {
        {
            LOCK(cs_KeyStore);
            KeyPairMap::const_iterator mi = mapKeyPairs.find(pairID);
            if (mi != mapKeyPairs.end())
            {
                keypair.Reset();
                keypair.SetSecrets((*mi).second.second.first, (*mi).second.second.second);
                return true;
            }
        }
        return false;
    }

    bool HaveKeyPair(const CPubKey &R, const CPubKey &vchPubKeyVariant, uint256 &pairID) const
    {
        {
            LOCK(cs_KeyStore);
            BOOST_FOREACH(const KeyPair &keyPair, mapKeyPairs)
            {
                CMutableKeyView mpv(keyPair.second.second.first, keyPair.second.first);

                if (mpv.CheckKeyVariant(R, vchPubKeyVariant))
                {
                    pairID = keyPair.first;
                    return true;
                }
            }
        }
        return false;
    }

    bool GetOneTimeKey(const CPubKey &R, const CPubKey &vchPubKeyVariant, CKey &oneTimeKeyOut, uint256 pairID) const
    {
        {
            LOCK(cs_KeyStore);
            CMutableKey keypair;
            if (!GetKeyPair(pairID, keypair))
                return false;

            if (keypair.CheckKeyVariant(R, vchPubKeyVariant, oneTimeKeyOut))
                return true;
        }

        return false;
    }
};


typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;

// Crypted key pair map
// Only second part of secret info is encrypted
typedef std::pair<uint256, std::pair<std::pair<CSecret, CPubKey>, std::vector<unsigned char> > > CryptedKeyPair;
typedef std::map<uint256, std::pair<std::pair<CSecret, CPubKey>, std::vector<unsigned char> > > CryptedKeyPairMap;

/** Keystore which keeps the private keys encrypted.
 * It derives from the basic key store, which is used if no encryption is active.
 */
class CCryptoKeyStore : public CBasicKeyStore
{
private:
    CryptedKeyMap mapCryptedKeys;
    CryptedKeyPairMap mapCryptedKeyPairs;

    CKeyingMaterial vMasterKey;

    // if fUseCrypto is true, mapKeys must be empty
    // if fUseCrypto is false, vMasterKey must be empty
    bool fUseCrypto;

protected:
    bool SetCrypted();

    // will encrypt previously unencrypted keys
    bool EncryptKeys(CKeyingMaterial& vMasterKeyIn);

    bool Unlock(const CKeyingMaterial& vMasterKeyIn);

public:
    CCryptoKeyStore() : fUseCrypto(false)
    {
    }

    bool IsCrypted() const
    {
        return fUseCrypto;
    }

    bool IsLocked() const
    {
        if (!IsCrypted())
            return false;
        bool result;
        {
            LOCK(cs_KeyStore);
            result = vMasterKey.empty();
        }
        return result;
    }

    bool Lock();

    virtual bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    virtual bool AddCryptedKeyPair(const uint256 &keyPairID, const CSecret &secretL, const CPubKey &vchPubKeyH, const std::vector<unsigned char> &vchCryptedSecretH);
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        {
            LOCK(cs_KeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::HaveKey(address);
            return mapCryptedKeys.count(address) > 0;
        }
        return false;
    }
    bool GetKey(const CKeyID &address, CKey& keyOut) const;
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        if (!IsCrypted())
        {
            CBasicKeyStore::GetKeys(setAddress);
            return;
        }
        setAddress.clear();
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        while (mi != mapCryptedKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
    }

    bool AddKeyPair(const CMutableKey& key);
    bool HaveKeyPair(const uint256 &keyPairID) const
    {
        {
            LOCK(cs_KeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::HaveKeyPair(keyPairID);
            return mapCryptedKeyPairs.count(keyPairID) > 0;
        }
        return false;
    }
    bool GetKeyPair(const uint256 &keyPairID, CMutableKey& keyPairOut) const;

    bool HaveKeyPair(const CPubKey &R, const CPubKey &vchPubKeyVariant, uint256 &pairID) const
    {
        {
            LOCK(cs_KeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::HaveKeyPair(R, vchPubKeyVariant, pairID);
            BOOST_FOREACH(const CryptedKeyPair &keyPair, mapCryptedKeyPairs)
            {
                CMutableKeyView mpv(keyPair.second.first.first, keyPair.second.first.second);

                if (mpv.CheckKeyVariant(R, vchPubKeyVariant))
                {
                    pairID = keyPair.first;
                    return true;
                }
            }
        }
        return false;
    }

    bool GetOneTimeKey(const CPubKey &R, const CPubKey &vchPubKeyVariant, CKey &oneTimeKeyOut, uint256 pairID) const
    {
        {
            LOCK(cs_KeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::GetOneTimeKey(R, vchPubKeyVariant, oneTimeKeyOut, pairID);

            CMutableKey keypair;
            if (!GetKeyPair(pairID, keypair))
                return false;

            if (keypair.CheckKeyVariant(R, vchPubKeyVariant, oneTimeKeyOut))
                return true;
        }

        return false;
    }

    /* Wallet status (encrypted, locked) changed.
     * Note: Called without locks held.
     */
    boost::signals2::signal<void (CCryptoKeyStore* wallet)> NotifyStatusChanged;
};

#endif
