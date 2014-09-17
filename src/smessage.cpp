// Copyright (c) 2014 The ShadowCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
Notes:
    Running with -debug could leave to and from address hashes and public keys in the log.
    
    
    parameters:
        -nosmsg             Disable secure messaging (fNoSmsg)
        -debugsmsg          Show extra debug messages (fDebugSmsg)
        -smsgscanchain      Scan the block chain for public key addresses on startup
    
    
    Wallet Locked
        A copy of each incoming message is stored in bucket files ending in _wl.dat
        wl (wallet locked) bucket files are deleted if they expire, like normal buckets
        When the wallet is unlocked all the messages in wl files are scanned.
    
    
    Address Whitelist
        Owned Addresses are stored in smsgAddresses vector
        Saved to smsg.ini
        Modify options using the smsglocalkeys rpc command or edit the smsg.ini file (with client closed)
        
    
*/

#include "smessage.h"

#include <stdint.h>
#include <time.h>
#include <map>
#include <stdexcept>
#include <sstream>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/predicate.hpp>


#include "base58.h"
#include "db.h"
#include "init.h" // pwalletMain
#include "txdb.h"


#include "lz4/lz4.c"

#include "xxhash/xxhash.h"
#include "xxhash/xxhash.c"


// On 64 bit system ld is 64bits
#ifdef IS_ARCH_64
#undef PRId64
#undef PRIu64
#undef PRIx64
#define PRId64  "ld"
#define PRIu64  "lu"
#define PRIx64  "lx"
#endif // IS_ARCH_64


// TODO: For buckets older than current, only need to store no. messages and hash in memory

boost::signals2::signal<void (SecMsgStored& inboxHdr)>  NotifySecMsgInboxChanged;
boost::signals2::signal<void (SecMsgStored& outboxHdr)> NotifySecMsgOutboxChanged;
boost::signals2::signal<void ()> NotifySecMsgWalletUnlocked;

bool fSecMsgEnabled = false;

std::map<int64_t, SecMsgBucket> smsgBuckets;
std::vector<SecMsgAddress>      smsgAddresses;
SecMsgOptions                   smsgOptions;

uint32_t nPeerIdCounter = 1;



CCriticalSection cs_smsg;
CCriticalSection cs_smsgDB;

leveldb::DB *smsgDB = NULL;


namespace fs = boost::filesystem;

bool SecMsgCrypter::SetKey(const std::vector<unsigned char>& vchNewKey, unsigned char* chNewIV)
{
    
    if (vchNewKey.size() < sizeof(chKey))
        return false;
    
    return SetKey(&vchNewKey[0], chNewIV);
};

bool SecMsgCrypter::SetKey(const unsigned char* chNewKey, unsigned char* chNewIV)
{
    // -- for EVP_aes_256_cbc() key must be 256 bit, iv must be 128 bit.
    memcpy(&chKey[0], chNewKey, sizeof(chKey));
    memcpy(chIV, chNewIV, sizeof(chIV));
    
    fKeySet = true;
    return true;
};

bool SecMsgCrypter::Encrypt(unsigned char* chPlaintext, uint32_t nPlain, std::vector<unsigned char> &vchCiphertext)
{
    if (!fKeySet)
        return false;
    
    // -- max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE - 1 bytes
    int nLen = nPlain;
    
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = std::vector<unsigned char> (nCLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    if (fOk) fOk = EVP_EncryptUpdate(&ctx, &vchCiphertext[0], &nCLen, chPlaintext, nLen);
    if (fOk) fOk = EVP_EncryptFinal_ex(&ctx, (&vchCiphertext[0])+nCLen, &nFLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk)
        return false;

    vchCiphertext.resize(nCLen + nFLen);
    
    return true;
};

bool SecMsgCrypter::Decrypt(unsigned char* chCiphertext, uint32_t nCipher, std::vector<unsigned char>& vchPlaintext)
{
    if (!fKeySet)
        return false;
    
    // plaintext will always be equal to or lesser than length of ciphertext
    int nPLen = nCipher, nFLen = 0;
    
    vchPlaintext.resize(nCipher);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    if (fOk) fOk = EVP_DecryptUpdate(&ctx, &vchPlaintext[0], &nPLen, &chCiphertext[0], nCipher);
    if (fOk) fOk = EVP_DecryptFinal_ex(&ctx, (&vchPlaintext[0])+nPLen, &nFLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk)
        return false;
    
    vchPlaintext.resize(nPLen + nFLen);
    
    return true;
};

void SecMsgBucket::hashBucket()
{
    if (fDebugSmsg)
        printf("SecMsgBucket::hashBucket()\n");
    
    timeChanged = GetTime();
    
    std::set<SecMsgToken>::iterator it;
    
    void* state = XXH32_init(1);
    
    for (it = setTokens.begin(); it != setTokens.end(); ++it)
    {
        XXH32_update(state, it->sample, 8);
    };
    
    hash = XXH32_digest(state);
    
    if (fDebugSmsg)
        printf("Hashed %"PRIszu" messages, hash %u\n", setTokens.size(), hash);
};


bool SecMsgDB::Open(const char* pszMode)
{
    if (smsgDB)
    {
        pdb = smsgDB;
        return true;
    };
    
    bool fCreate = strchr(pszMode, 'c');
    
    fs::path fullpath = GetDataDir() / "smsgDB";
    
    if (!fCreate
        && (!fs::exists(fullpath)
            || !fs::is_directory(fullpath)))
    {
        printf("SecMsgDB::open() - DB does not exist.\n");
        return false;
    };
    
    leveldb::Options options;
    options.create_if_missing = fCreate;
    leveldb::Status s = leveldb::DB::Open(options, fullpath.string(), &smsgDB);
    
    if (!s.ok())
    {
        printf("SecMsgDB::open() - Error opening db: %s.\n", s.ToString().c_str());
        return false;
    };
    
    pdb = smsgDB;
    
    return true;
};


class SecMsgBatchScanner : public leveldb::WriteBatch::Handler
{
public:
    std::string needle;
    bool* deleted;
    std::string* foundValue;
    bool foundEntry;
    
    SecMsgBatchScanner() : foundEntry(false) {}
    
    virtual void Put(const leveldb::Slice& key, const leveldb::Slice& value)
    {
        if (key.ToString() == needle)
        {
            foundEntry = true;
            *deleted = false;
            *foundValue = value.ToString();
        };
    };
    
    virtual void Delete(const leveldb::Slice& key)
    {
        if (key.ToString() == needle)
        {
            foundEntry = true;
            *deleted = true;
        };
    };
};

// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
bool SecMsgDB::ScanBatch(const CDataStream& key, std::string* value, bool* deleted) const
{
    if (!activeBatch)
        return false;
    
    *deleted = false;
    SecMsgBatchScanner scanner;
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    leveldb::Status s = activeBatch->Iterate(&scanner);
    if (!s.ok())
    {
        printf("SecMsgDB ScanBatch error: %s\n", s.ToString().c_str());
        return false;
    };
    
    return scanner.foundEntry;
}

bool SecMsgDB::TxnBegin()
{
    if (activeBatch)
        return true;
    activeBatch = new leveldb::WriteBatch();
    return true;
};

bool SecMsgDB::TxnCommit()
{
    if (!activeBatch)
        return false;
    
    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status status = pdb->Write(writeOptions, activeBatch);
    delete activeBatch;
    activeBatch = NULL;
    
    if (!status.ok())
    {
        printf("SecMsgDB batch commit failure: %s\n", status.ToString().c_str());
        return false;
    };
    
    return true;
};

bool SecMsgDB::TxnAbort()
{
    delete activeBatch;
    activeBatch = NULL;
    return true;
};

bool SecMsgDB::ReadPK(CKeyID& addr, CPubKey& pubkey)
{
    if (!pdb)
        return false;
    
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(sizeof(addr) + 2);
    ssKey << 'p';
    ssKey << 'k';
    ssKey << addr;
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch)
    {
        // -- check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted)
            return false;
    };
    
    if (readFromDb)
    {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok())
        {
            if (s.IsNotFound())
                return false;
            printf("LevelDB read failure: %s\n", s.ToString().c_str());
            return false;
        };
    };
    
    try {
        CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
        ssValue >> pubkey;
    } catch (std::exception& e) {
        printf("SecMsgDB::ReadPK() unserialize threw: %s.\n", e.what());
        return false;
    }
    
    return true;
};

bool SecMsgDB::WritePK(CKeyID& addr, CPubKey& pubkey)
{
    if (!pdb)
        return false;
    
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(sizeof(addr) + 2);
    ssKey << 'p';
    ssKey << 'k';
    ssKey << addr;
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssValue.reserve(sizeof(pubkey));
    ssValue << pubkey;

    if (activeBatch)
    {
        activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    };
    
    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok())
    {
        printf("SecMsgDB write failure: %s\n", s.ToString().c_str());
        return false;
    };
    
    return true;
};

bool SecMsgDB::ExistsPK(CKeyID& addr)
{
    if (!pdb)
        return false;
    
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(sizeof(addr)+2);
    ssKey << 'p';
    ssKey << 'k';
    ssKey << addr;
    std::string unused;
    
    if (activeBatch)
    {
        bool deleted;
        if (ScanBatch(ssKey, &unused, &deleted) && !deleted)
        {
            return true;
        };
    };
    
    leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
    return s.IsNotFound() == false;
};


bool SecMsgDB::NextSmesg(leveldb::Iterator* it, std::string& prefix, unsigned char* chKey, SecMsgStored& smsgStored)
{
    if (!pdb)
        return false;
    
    if (!it->Valid()) // first run
        it->Seek(prefix);
    else
        it->Next();
    
    if (!(it->Valid()
        && it->key().size() == 18
        && memcmp(it->key().data(), prefix.data(), 2) == 0))
        return false;
    
    memcpy(chKey, it->key().data(), 18);
    
    try {
        CDataStream ssValue(it->value().data(), it->value().data() + it->value().size(), SER_DISK, CLIENT_VERSION);
        ssValue >> smsgStored;
    } catch (std::exception& e) {
        printf("SecMsgDB::NextSmesg() unserialize threw: %s.\n", e.what());
        return false;
    }
    
    return true;
};

bool SecMsgDB::NextSmesgKey(leveldb::Iterator* it, std::string& prefix, unsigned char* chKey)
{
    if (!pdb)
        return false;
    
    if (!it->Valid()) // first run
        it->Seek(prefix);
    else
        it->Next();
    
    if (!(it->Valid()
        && it->key().size() == 18
        && memcmp(it->key().data(), prefix.data(), 2) == 0))
        return false;
    
    memcpy(chKey, it->key().data(), 18);
    
    return true;
};

bool SecMsgDB::ReadSmesg(unsigned char* chKey, SecMsgStored& smsgStored)
{
    if (!pdb)
        return false;
    
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.write((const char*)chKey, 18);
    std::string strValue;

    bool readFromDb = true;
    if (activeBatch)
    {
        // -- check activeBatch first
        bool deleted = false;
        readFromDb = ScanBatch(ssKey, &strValue, &deleted) == false;
        if (deleted)
            return false;
    };
    
    if (readFromDb)
    {
        leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &strValue);
        if (!s.ok())
        {
            if (s.IsNotFound())
                return false;
            printf("LevelDB read failure: %s\n", s.ToString().c_str());
            return false;
        };
    };
    
    try {
        CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
        ssValue >> smsgStored;
    } catch (std::exception& e) {
        printf("SecMsgDB::ReadSmesg() unserialize threw: %s.\n", e.what());
        return false;
    }
    
    return true;
};

bool SecMsgDB::WriteSmesg(unsigned char* chKey, SecMsgStored& smsgStored)
{
    if (!pdb)
        return false;
    
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.write((const char*)chKey, 18);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssValue << smsgStored;

    if (activeBatch)
    {
        activeBatch->Put(ssKey.str(), ssValue.str());
        return true;
    };
    
    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Put(writeOptions, ssKey.str(), ssValue.str());
    if (!s.ok())
    {
        printf("SecMsgDB write failed: %s\n", s.ToString().c_str());
        return false;
    };
    
    return true;
};

bool SecMsgDB::ExistsSmesg(unsigned char* chKey)
{
    if (!pdb)
        return false;
    
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.write((const char*)chKey, 18);
    std::string unused;
    
    if (activeBatch)
    {
        bool deleted;
        if (ScanBatch(ssKey, &unused, &deleted) && !deleted)
        {
            return true;
        };
    };
    
    leveldb::Status s = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
    return s.IsNotFound() == false;
    return true;
};

bool SecMsgDB::EraseSmesg(unsigned char* chKey)
{
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.write((const char*)chKey, 18);
    
    if (activeBatch)
    {
        activeBatch->Delete(ssKey.str());
        return true;
    };
    
    leveldb::WriteOptions writeOptions;
    writeOptions.sync = true;
    leveldb::Status s = pdb->Delete(writeOptions, ssKey.str());
    
    if (s.ok() || s.IsNotFound())
        return true;
    printf("SecMsgDB erase failed: %s\n", s.ToString().c_str());
    return false;
};

void ThreadSecureMsg(void* parg)
{
    // -- bucket management thread
    RenameThread("shadowcoin-smsg"); // Make this thread recognisable
    
    uint32_t delay = 0;
    
    while (fSecMsgEnabled)
    {
        // shutdown thread waits 5 seconds, this should be less
        MilliSleep(1000); // milliseconds
        
        if (!fSecMsgEnabled) // check again after sleep
            break;
        
        delay++;
        if (delay < SMSG_THREAD_DELAY) // check every SMSG_THREAD_DELAY seconds
            continue;
        delay = 0;
        
        int64_t now = GetTime();
        
        if (fDebugSmsg)
            printf("SecureMsgThread %"PRId64" \n", now);
        
        int64_t cutoffTime = now - SMSG_RETENTION;
        
        {
            LOCK(cs_smsg);
            std::map<int64_t, SecMsgBucket>::iterator it;
            it = smsgBuckets.begin();
            
            while (it != smsgBuckets.end())
            {
                //if (fDebugSmsg)
                //    printf("Checking bucket %"PRId64", size %"PRIszu" \n", it->first, it->second.setTokens.size());
                if (it->first < cutoffTime)
                {
                    if (fDebugSmsg)
                        printf("Removing bucket %"PRId64" \n", it->first);
                    std::string fileName = boost::lexical_cast<std::string>(it->first) + "_01.dat";
                    fs::path fullPath = GetDataDir() / "smsgStore" / fileName;
                    if (fs::exists(fullPath))
                    {
                        try {
                            fs::remove(fullPath);
                        } catch (const fs::filesystem_error& ex)
                        {
                            printf("Error removing bucket file %s.\n", ex.what());
                        };
                    } else
                        printf("Path %s does not exist \n", fullPath.string().c_str());
                    
                    // -- look for a wl file, it stores incoming messages when wallet is locked
                    fileName = boost::lexical_cast<std::string>(it->first) + "_01_wl.dat";
                    fullPath = GetDataDir() / "smsgStore" / fileName;
                    if (fs::exists(fullPath))
                    {
                        try {
                            fs::remove(fullPath);
                        } catch (const fs::filesystem_error& ex)
                        {
                            printf("Error removing wallet locked file %s.\n", ex.what());
                        };
                    };
                    
                    smsgBuckets.erase(it++);
                } else
                {
                    // -- tick down nLockCount, so will eventually expire if peer never sends data
                    if (it->second.nLockCount > 0)
                    {
                        it->second.nLockCount--;
                        
                        if (it->second.nLockCount == 0)     // lock timed out
                        {
                            uint32_t    nPeerId     = it->second.nLockPeerId;
                            int64_t     ignoreUntil = GetTime() + SMSG_TIME_IGNORE;
                            
                            if (fDebugSmsg)
                                printf("Lock on bucket %"PRId64" for peer %u timed out.\n", it->first, nPeerId);
                            // -- look through the nodes for the peer that locked this bucket
                            LOCK(cs_vNodes);
                            BOOST_FOREACH(CNode* pnode, vNodes)
                            {
                                if (pnode->smsgData.nPeerId != nPeerId)
                                    continue;
                                pnode->smsgData.ignoreUntil = ignoreUntil;
                                
                                // -- alert peer that they are being ignored
                                std::vector<unsigned char> vchData;
                                vchData.resize(8);
                                memcpy(&vchData[0], &ignoreUntil, 8);
                                pnode->PushMessage("smsgIgnore", vchData);
                                
                                if (fDebugSmsg)
                                    printf("This node will ignore peer %u until %"PRId64".\n", nPeerId, ignoreUntil);
                                break;
                            };
                            it->second.nLockPeerId = 0;
                        }; // if (it->second.nLockCount == 0)
                    };
                    ++it;
                }; // ! if (it->first < cutoffTime)
            };
        }; // LOCK(cs_smsg);
    };
    
    printf("ThreadSecureMsg exited.\n");
};

void ThreadSecureMsgPow(void* parg)
{
    // -- proof of work thread
    RenameThread("shadowcoin-smsg-pow"); // Make this thread recognisable
    
    int rv;
    std::vector<unsigned char> vchKey;
    SecMsgStored smsgStored;
    
    std::string sPrefix("qm");
    unsigned char chKey[18];
    
    
    while (fSecMsgEnabled)
    {
        // -- sleep at end, then fSecMsgEnabled is tested on wake
        
        SecMsgDB dbOutbox;
        leveldb::Iterator* it;
        {
            LOCK(cs_smsgDB);
            
            if (!dbOutbox.Open("cr+"))
                continue;
            
            // -- fifo (smallest key first)
            it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());
        }
        // -- break up lock, SecureMsgSetHash will take long
        
        for (;;)
        {
            {
                LOCK(cs_smsgDB); 
                if (!dbOutbox.NextSmesg(it, sPrefix, chKey, smsgStored))
                    break;
            }
            
            unsigned char* pHeader = &smsgStored.vchMessage[0];
            unsigned char* pPayload = &smsgStored.vchMessage[SMSG_HDR_LEN];
            SecureMessage* psmsg = (SecureMessage*) pHeader;
            
            // -- do proof of work
            rv = SecureMsgSetHash(pHeader, pPayload, psmsg->nPayload);
            if (rv == 2) 
                break; // /eave message in db, if terminated due to shutdown
            
            // -- message is removed here, no matter what
            {
                LOCK(cs_smsgDB);
                dbOutbox.EraseSmesg(chKey);
            }
            if (rv != 0)
            {
                printf("SecMsgPow: Could not get proof of work hash, message removed.\n");
                continue;
            };
            
            // -- add to message store
            {
                LOCK(cs_smsg);
                if (SecureMsgStore(pHeader, pPayload, psmsg->nPayload, true) != 0)
                {
                    printf("SecMsgPow: Could not place message in buckets, message removed.\n");
                    continue;
                };
            }
            
            // -- test if message was sent to self
            if (SecureMsgScanMessage(pHeader, pPayload, psmsg->nPayload, true) != 0)
            {
                // message recipient is not this node (or failed)
            };
        };
        
        {
            LOCK(cs_smsg);
            delete it;
        }
        
        // -- shutdown thread waits 5 seconds, this should be less
        MilliSleep(1000); // milliseconds
    };
    
    printf("ThreadSecureMsgPow exited.\n");
};


std::string getTimeString(int64_t timestamp, char *buffer, size_t nBuffer)
{
    struct tm* dt;
    time_t t = timestamp;
    dt = localtime(&t);
    
    strftime(buffer, nBuffer, "%Y-%m-%d %H:%M:%S %z", dt); // %Z shows long strings on windows
    return std::string(buffer); // copies the null-terminated character sequence
};

std::string fsReadable(uint64_t nBytes)
{
    char buffer[128];
    if (nBytes >= 1024ll*1024ll*1024ll*1024ll)
        snprintf(buffer, sizeof(buffer), "%.2f TB", nBytes/1024.0/1024.0/1024.0/1024.0);
    else
    if (nBytes >= 1024*1024*1024)
        snprintf(buffer, sizeof(buffer), "%.2f GB", nBytes/1024.0/1024.0/1024.0);
    else
    if (nBytes >= 1024*1024)
        snprintf(buffer, sizeof(buffer), "%.2f MB", nBytes/1024.0/1024.0);
    else
    if (nBytes >= 1024)
        snprintf(buffer, sizeof(buffer), "%.2f KB", nBytes/1024.0);
    else
        snprintf(buffer, sizeof(buffer), "%"PRIu64" bytes", nBytes);
    return std::string(buffer);
};

int SecureMsgBuildBucketSet()
{
    /*
        Build the bucket set by scanning the files in the smsgStore dir.
        
        smsgBuckets should be empty
    */
    
    if (fDebugSmsg)
        printf("SecureMsgBuildBucketSet()\n");
        
    int64_t  now            = GetTime();
    uint32_t nFiles         = 0;
    uint32_t nMessages      = 0;
    
    fs::path pathSmsgDir = GetDataDir() / "smsgStore";
    fs::directory_iterator itend;
    
    
    if (!fs::exists(pathSmsgDir)
        || !fs::is_directory(pathSmsgDir))
    {
        printf("Message store directory does not exist.\n");
        return 0; // not an error
    }
    
    
    for (fs::directory_iterator itd(pathSmsgDir) ; itd != itend ; ++itd)
    {
        if (!fs::is_regular_file(itd->status()))
            continue;
        
        std::string fileType = (*itd).path().extension().string();
        
        if (fileType.compare(".dat") != 0)
            continue;
            
        std::string fileName = (*itd).path().filename().string();
        
        
        if (fDebugSmsg)
            printf("Processing file: %s.\n", fileName.c_str());
        
        nFiles++;
        
        // TODO files must be split if > 2GB
        // time_noFile.dat
        size_t sep = fileName.find_first_of("_");
        if (sep == std::string::npos)
            continue;
        
        std::string stime = fileName.substr(0, sep);
        
        int64_t fileTime = boost::lexical_cast<int64_t>(stime);
        
        if (fileTime < now - SMSG_RETENTION)
        {
            printf("Dropping file %s, expired.\n", fileName.c_str());
            try {
                fs::remove((*itd).path());
            } catch (const fs::filesystem_error& ex)
            {
                printf("Error removing bucket file %s, %s.\n", fileName.c_str(), ex.what());
            };
            continue;
        };
        
        if (boost::algorithm::ends_with(fileName, "_wl.dat"))
        {
            if (fDebugSmsg)
                printf("Skipping wallet locked file: %s.\n", fileName.c_str());
            continue;
        };
        
        
        SecureMessage smsg;
        std::set<SecMsgToken>& tokenSet = smsgBuckets[fileTime].setTokens;
        
        {
            LOCK(cs_smsg);
            FILE *fp;
            
            if (!(fp = fopen((*itd).path().string().c_str(), "rb")))
            {
                printf("Error opening file: %s\n", strerror(errno));
                continue;
            };
            
            for (;;)
            {
                long int ofs = ftell(fp);
                SecMsgToken token;
                token.offset = ofs;
                errno = 0;
                if (fread(&smsg.hash[0], sizeof(unsigned char), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
                {
                    if (errno != 0)
                    {
                        printf("fread header failed: %s\n", strerror(errno));
                    } else
                    {
                        //printf("End of file.\n");
                    };
                    break;
                };
                token.timestamp = smsg.timestamp;
                
                if (smsg.nPayload < 8)
                    continue;
                
                if (fread(token.sample, sizeof(unsigned char), 8, fp) != 8)
                {
                    printf("fread data failed: %s\n", strerror(errno));
                    break;
                };
                
                if (fseek(fp, smsg.nPayload-8, SEEK_CUR) != 0)
                {
                    printf("fseek, strerror: %s.\n", strerror(errno));
                    break;
                };
                
                tokenSet.insert(token);
            };
            
            fclose(fp);
        };
        smsgBuckets[fileTime].hashBucket();
        
        nMessages += tokenSet.size();
        
        if (fDebugSmsg)
            printf("Bucket %"PRId64" contains %"PRIszu" messages.\n", fileTime, tokenSet.size());
    };
    
    printf("Processed %u files, loaded %"PRIszu" buckets containing %u messages.\n", nFiles, smsgBuckets.size(), nMessages);
    
    return 0;
};

int SecureMsgAddWalletAddresses()
{
    if (fDebugSmsg)
        printf("SecureMsgAddWalletAddresses()\n");
    
    uint32_t nAdded = 0;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& entry, pwalletMain->mapAddressBook)
    {
        if (!IsMine(*pwalletMain, entry.first))
            continue;
        
        CBitcoinAddress coinAddress(entry.first);
        if (!coinAddress.IsValid())
            continue;
        
        std::string address;
        std::string strPublicKey;
        address = coinAddress.ToString();
        
        
        bool fExists        = 0;
        for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
        {
            if (address != it->sAddress)
                continue;
            fExists = 1;
            break;
        };
        
        if (fExists)
            continue;
        
        bool recvEnabled    = 1;
        bool recvAnon       = 1;
        
        smsgAddresses.push_back(SecMsgAddress(address, recvEnabled, recvAnon));
        nAdded++;
    };
    
    if (fDebugSmsg)
        printf("Added %u addresses to whitelist.\n", nAdded);
    
    return 0;
};


int SecureMsgReadIni()
{
    if (!fSecMsgEnabled)
        return false;
    
    if (fDebugSmsg)
        printf("SecureMsgReadIni()\n");
    
    fs::path fullpath = GetDataDir() / "smsg.ini";
    
    
    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "r")))
    {
        printf("Error opening file: %s\n", strerror(errno));
        return 1;
    };
    
    char cLine[512];
    char *pName, *pValue;
    
    char cAddress[64];
    int addrRecv, addrRecvAnon;
    
    while (fgets(cLine, 512, fp))
    {
        cLine[strcspn(cLine, "\n")] = '\0';
        cLine[strcspn(cLine, "\r")] = '\0';
        cLine[511] = '\0'; // for safety
        
        // -- check that line contains a name value pair and is not a comment, or section header
        if (cLine[0] == '#' || cLine[0] == '[' || strcspn(cLine, "=") < 1)
            continue;
        
        if (!(pName = strtok(cLine, "="))
            || !(pValue = strtok(NULL, "=")))
            continue;
        
        if (strcmp(pName, "newAddressRecv") == 0)
        {
            smsgOptions.fNewAddressRecv = (strcmp(pValue, "true") == 0) ? true : false;
        } else
        if (strcmp(pName, "newAddressAnon") == 0)
        {
            smsgOptions.fNewAddressAnon = (strcmp(pValue, "true") == 0) ? true : false;
        } else
        if (strcmp(pName, "key") == 0)
        {
            int rv = sscanf(pValue, "%64[^|]|%d|%d", cAddress, &addrRecv, &addrRecvAnon);
            if (rv == 3)
            {
                smsgAddresses.push_back(SecMsgAddress(std::string(cAddress), addrRecv, addrRecvAnon));
            } else
            {
                printf("Could not parse key line %s, rv %d.\n", pValue, rv);
            }
        } else
        {
            printf("Unknown setting name: '%s'.", pName);
        };
    };
    
    printf("Loaded %"PRIszu" addresses.\n", smsgAddresses.size());
    
    fclose(fp);
    
    return 0;
};

int SecureMsgWriteIni()
{
    if (!fSecMsgEnabled)
        return false;
    
    if (fDebugSmsg)
        printf("SecureMsgWriteIni()\n");
    
    fs::path fullpath = GetDataDir() / "smsg.ini~";
    
    FILE *fp;
    errno = 0;
    if (!(fp = fopen(fullpath.string().c_str(), "w")))
    {
        printf("Error opening file: %s\n", strerror(errno));
        return 1;
    };
    
    if (fwrite("[Options]\n", sizeof(char), 10, fp) != 10)
    {
        printf("fwrite error: %s\n", strerror(errno));
        fclose(fp);
        return false;
    };
    
    if (fprintf(fp, "newAddressRecv=%s\n", smsgOptions.fNewAddressRecv ? "true" : "false") < 0
        || fprintf(fp, "newAddressAnon=%s\n", smsgOptions.fNewAddressAnon ? "true" : "false") < 0)
    {
        printf("fprintf error: %s\n", strerror(errno));
        fclose(fp);
        return false;
    }
    
    if (fwrite("\n[Keys]\n", sizeof(char), 8, fp) != 8)
    {
        printf("fwrite error: %s\n", strerror(errno));
        fclose(fp);
        return false;
    };
    for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
    {
        errno = 0;
        if (fprintf(fp, "key=%s|%d|%d\n", it->sAddress.c_str(), it->fReceiveEnabled, it->fReceiveAnon) < 0)
        {
            printf("fprintf error: %s\n", strerror(errno));
            continue;
        };
    };
    
    
    fclose(fp);
    
    
    try {
        fs::path finalpath = GetDataDir() / "smsg.ini";
        fs::rename(fullpath, finalpath);
    } catch (const fs::filesystem_error& ex)
    {
        printf("Error renaming file %s, %s.\n", fullpath.string().c_str(), ex.what());
    };
    return 0;
};


/** called from AppInit2() in init.cpp */
bool SecureMsgStart(bool fDontStart, bool fScanChain)
{
    if (fDontStart)
    {
        printf("Secure messaging not started.\n");
        return false;
    };
    
    printf("Secure messaging starting.\n");
    
    fSecMsgEnabled = true;
    
    if (SecureMsgReadIni() != 0)
        printf("Failed to read smsg.ini\n");
    
    if (smsgAddresses.size() < 1)
    {
        printf("No address keys loaded.\n");
        if (SecureMsgAddWalletAddresses() != 0)
            printf("Failed to load addresses from wallet.\n");
    };
    
    if (fScanChain)
    {
        SecureMsgScanBlockChain();
    };
    
    if (SecureMsgBuildBucketSet() != 0)
    {
        printf("SecureMsg could not load bucket sets, secure messaging disabled.\n");
        fSecMsgEnabled = false;
        return false;
    };
    
    // -- start threads
    if (!NewThread(ThreadSecureMsg, NULL)
        || !NewThread(ThreadSecureMsgPow, NULL))
    {
        printf("SecureMsg could not start threads, secure messaging disabled.\n");
        fSecMsgEnabled = false;
        return false;
    };
    
    return true;
};

/** called from Shutdown() in init.cpp */
bool SecureMsgShutdown()
{
    if (!fSecMsgEnabled)
        return false;
    
    printf("Stopping secure messaging.\n");
    
    
    if (SecureMsgWriteIni() != 0)
        printf("Failed to save smsg.ini\n");
    
    fSecMsgEnabled = false;
    
    if (smsgDB)
    {
        LOCK(cs_smsgDB);
        delete smsgDB;
        smsgDB = NULL;
    };
    
    // -- main program will wait 5 seconds for threads to terminate.
    
    return true;
};

bool SecureMsgEnable()
{
    // -- start secure messaging at runtime
    if (fSecMsgEnabled)
    {
        printf("SecureMsgEnable: secure messaging is already enabled.\n");
        return false;
    };
    
    {
        LOCK(cs_smsg);
        fSecMsgEnabled = true;
        
        smsgAddresses.clear(); // should be empty already
        if (SecureMsgReadIni() != 0)
            printf("Failed to read smsg.ini\n");
        
        if (smsgAddresses.size() < 1)
        {
            printf("No address keys loaded.\n");
            if (SecureMsgAddWalletAddresses() != 0)
                printf("Failed to load addresses from wallet.\n");
        };
        
        smsgBuckets.clear(); // should be empty already
        
        if (SecureMsgBuildBucketSet() != 0)
        {
            printf("SecureMsgEnable: could not load bucket sets, secure messaging disabled.\n");
            fSecMsgEnabled = false;
            return false;
        };
        
    }; // LOCK(cs_smsg);
    
    // -- start threads
    if (!NewThread(ThreadSecureMsg, NULL)
        || !NewThread(ThreadSecureMsgPow, NULL))
    {
        printf("SecureMsgEnable could not start threads, secure messaging disabled.\n");
        fSecMsgEnabled = false;
        return false;
    };
    
    // -- ping each peer, don't know which have messaging enabled
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            pnode->PushMessage("smsgPing");
            pnode->PushMessage("smsgPong"); // Send pong as have missed initial ping sent by peer when it connected
        };
    }
    
    printf("Secure messaging enabled.\n");
    return true;
};

bool SecureMsgDisable()
{
    // -- stop secure messaging at runtime
    if (!fSecMsgEnabled)
    {
        printf("SecureMsgDisable: secure messaging is already disabled.\n");
        return false;
    };
    
    {
        LOCK(cs_smsg);
        fSecMsgEnabled = false;
        
        // -- clear smsgBuckets
        std::map<int64_t, SecMsgBucket>::iterator it;
        it = smsgBuckets.begin();
        for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it)
        {
            it->second.setTokens.clear();
        };
        smsgBuckets.clear();
        
        // -- tell each smsg enabled peer that this node is disabling
        {
            LOCK(cs_vNodes);
            
