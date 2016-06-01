#include "CertList.h"
#include <dirent.h>
#include "../util/sys_utils.h"
#include <unistd.h>

char g_gencerts_dir[MAX_PATH] = {0};
std::map<boost::asio::ip::tcp::endpoint, Certificate *> g_cert_list;

void set_gencerts_dir(const char *dirname)
{
    strcpy(g_gencerts_dir, dirname);
    strcat(g_gencerts_dir, "/gencerts");
    if (0 != access(g_gencerts_dir, 0))
    {
        multi_mkdir(g_gencerts_dir, 0755);
    }

    fprintf(stdout, "generated certs path: %s\n", g_gencerts_dir);
}

bool read_cert_file(const char *filename)
{
    char ip[20];
    int port;
    X509 *cert;
    EVP_PKEY *pkey;
    char fullpath[MAX_PATH];
    boost::asio::ip::tcp::endpoint endpoint;
    FILE *fp;
    
    char *end_ip = strchr(filename, '-');
    if(end_ip == NULL) {
        return false;
    }
    if(end_ip - filename >= sizeof(ip)-1) {
        return false;
    }
    memset(ip, 0, sizeof(ip));
    memcpy(ip, filename, end_ip-filename);
    port = atoi(end_ip+1);
    
    endpoint.address(boost::asio::ip::address::from_string(ip));
    endpoint.port(port);
    
    sprintf(fullpath, "%s/%s", g_gencerts_dir, filename);
    fp = fopen(fullpath, "rb");
    if(fp == NULL) {
        return false;
    }

    cert = PEM_read_X509(
        fp,
        NULL,
        NULL,
        NULL);

    pkey = PEM_read_PrivateKey(
        fp,
        NULL,
        NULL,
        NULL);

    fclose(fp);
    
    if(cert == NULL || pkey == NULL) {
        return false;
    }

    Certificate *leaf = new Certificate();
    leaf->setCert(cert);
    leaf->setKey(pkey);
    g_cert_list[endpoint] = leaf;
}

void load_certs_from_dir(const char *dirname)
{
    DIR *dp;
    struct dirent *entry;
    if((dp = opendir(dirname)) == NULL) {
        fprintf(stderr,"cannot open directory: %s\n", dirname);
        return;
    }
    while((entry = readdir(dp)) != NULL) {
        if(!(entry->d_type & DT_DIR)) {
            read_cert_file(entry->d_name);
        }    
    }
    closedir(dp);
}

void load_gencerts()
{
    load_certs_from_dir(g_gencerts_dir);
}

bool save_cert(const boost::asio::ip::tcp::endpoint &endpoint, Certificate* cert)
{
    g_cert_list[endpoint] = cert;
    char key_file[260];
    FILE * fp;
#if 0    
    char short_servername[260];
    memset(short_servername, 0, sizeof(short_servername));
    for(int i = 0, j = 0; i < this->serverName.length() && j < 16; i++) {
        if(isalpha(this->serverName[i]) || isdigit(this->serverName[i])) {
           short_servername[j++] = this->serverName[i];   
        }
    }
#endif 
    sprintf(key_file,
        "%s/%s-%d",
        g_gencerts_dir,
        endpoint.address().to_string().c_str(),
        endpoint.port());
    fp = fopen(key_file, "wb");
    if(fp != NULL) {
        PEM_write_X509(
            fp,   /* write the certificate to the file we've opened */
            cert->getCert() /* our certificate */
        );
        PEM_write_PrivateKey(
            fp,                  /* write the key to the file we've opened */
            cert->getKey(),               /* our key from earlier */
            NULL,               /* default cipher for encrypting the key on disk */
            NULL,                 /* passphrase required for decrypting the key on disk */
            0,                 /* length of the passphrase string */
            NULL,               /* callback for requesting a password */
            NULL                /* data to pass to the callback */
        );
        fclose(fp);
    }

    return true;
}

Certificate *find_cert(const boost::asio::ip::tcp::endpoint &endpoint)
{
    std::map<boost::asio::ip::tcp::endpoint, Certificate *>::iterator iter = g_cert_list.find(endpoint);
    if(iter != g_cert_list.end()) {
        return iter->second;
    }
    else {
        return NULL;
    }
}
