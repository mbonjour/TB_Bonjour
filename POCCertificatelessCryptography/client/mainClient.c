#include <sys/stat.h>
#include "mainClient.h"

#define PORT 10002

char *payload_text[10];
struct upload_status {
    int lines_read;
};
static void display_mailbox_list(struct mailimf_mailbox_list * mb_list, char *dest)
{
    clistiter * cur;

    for(cur = clist_begin(mb_list->mb_list) ; cur != NULL ;
        cur = clist_next(cur)) {
        struct mailimf_mailbox * mb;

        mb = clist_content(cur);

        //display_mailbox(mb);
        if (mb->mb_display_name != NULL) {
            strcat(dest, mb->mb_display_name);
            strcat(dest, " ");
        }
        //printf("<%s>", mb->mb_addr_spec);
        strcat(dest, mb->mb_addr_spec);
        if (clist_next(cur) != NULL) {
            strcat(dest, ", ");
        }
    }
}
static void display_address_list(struct mailimf_address_list * addr_list, char *dest)
{
    clistiter * cur;

    for(cur = clist_begin(addr_list->ad_list) ; cur != NULL ;
        cur = clist_next(cur)) {
        struct mailimf_address * addr;

        addr = clist_content(cur);

        switch (addr->ad_type) {
            case MAILIMF_ADDRESS_GROUP:
                strcat(dest, addr->ad_data.ad_group->grp_display_name);
                strcat(dest, ": ");
                clistiter * current;
                for(current = clist_begin(addr->ad_data.ad_group->grp_mb_list->mb_list) ; current != NULL ; current = clist_next(current)) {
                    struct mailimf_mailbox * mb;

                    mb = clist_content(current);
                    if (mb->mb_display_name != NULL) {
                        strcat(dest, mb->mb_display_name);
                        strcat(dest, " ");
                    }
                    //printf("<%s>", mb->mb_addr_spec);
                    strcat(dest, mb->mb_addr_spec);
                }
                strcat(dest, "; ");
                break;

            case MAILIMF_ADDRESS_MAILBOX:
                if (addr->ad_data.ad_mailbox->mb_display_name != NULL) {
                    strcat(dest, addr->ad_data.ad_mailbox->mb_display_name);
                    strcat(dest, " ");
                }
                //printf("<%s>", addr->ad_data.ad_mailbox->mb_addr_spec);
                strcat(dest, addr->ad_data.ad_mailbox->mb_addr_spec);
                break;
        }

        if (clist_next(cur) != NULL) {
            strcat(dest, ", ");
        }
    }
}

binn* parseEmail(char* filename){
    FILE *file;
    binn *mailReturn;
    mailReturn = binn_object();

    char* test = malloc(50);
    memset(test, 0, 50);
    strcat(test, "download/");
    strcat(test, filename);
    int r;
    struct mailmime * mime;
    struct stat stat_info;
    char * data;
    size_t current_index;

    file = fopen(test, "r");
    if (file == NULL) {
        exit(EXIT_FAILURE);
    }

    r = stat(test, &stat_info);
    if (r != 0) {
        fclose(file);
        exit(EXIT_FAILURE);
    }

    data = malloc(stat_info.st_size);
    fread(data, 1, stat_info.st_size, file);
    fclose(file);

    current_index = 0;
    r = mailmime_parse(data, stat_info.st_size,
                       &current_index, &mime);
    if (r != MAILIMF_NO_ERROR) {
        free(data);
        exit(EXIT_FAILURE);
        return EXIT_FAILURE;
    }

    // display_mime(mime);
    if (mime->mm_data.mm_message.mm_fields) {
        if (clist_begin(mime->mm_data.mm_message.mm_fields->fld_list) != NULL) {
            clistiter * cur;

            for(cur = clist_begin(mime->mm_data.mm_message.mm_fields->fld_list) ; cur != NULL ;
                cur = clist_next(cur)) {
                struct mailimf_field * f;

                f = clist_content(cur);
                switch (f->fld_type) {
                    case MAILIMF_FIELD_ORIG_DATE:
                        printf("\n");
                        char *dateFormat = malloc(50);
                        struct mailimf_date_time * d = f->fld_data.fld_orig_date->dt_date_time;
                        snprintf(dateFormat, 50, "%02i/%02i/%i %02i:%02i:%02i %+04i",
                               d->dt_day, d->dt_month, d->dt_year,
                               d->dt_hour, d->dt_min, d->dt_sec, d->dt_zone);
                        binn_object_set_str(mailReturn, "Date", dateFormat);
                        free(dateFormat);
                        break;
                    case MAILIMF_FIELD_FROM:
                        printf("\n");
                        char *fromList = malloc(256);
                        memset(fromList,0,256);
                        display_mailbox_list(f->fld_data.fld_from->frm_mb_list, fromList);
                        //printf("\n");
                        binn_object_set_str(mailReturn, "From", fromList);
                        free(fromList);
                        break;
                    case MAILIMF_FIELD_TO:
                        printf("\n");
                        char *toList = malloc(256);
                        memset(toList,0,256);
                        //display_to(f->fld_data.fld_to);
                        display_address_list(f->fld_data.fld_to->to_addr_list, toList);
                        //printf("\n");
                        binn_object_set_str(mailReturn, "To", toList);
                        free(toList);
                        break;
                    case MAILIMF_FIELD_CC:
                        printf("\n");
                        char *ccList = malloc(256);
                        memset(ccList,0,256);
                        //display_cc(f->fld_data.fld_cc);
                        display_address_list(f->fld_data.fld_cc->cc_addr_list, ccList);
                        //printf("\n");
                        binn_object_set_str(mailReturn, "CC", ccList);
                        free(ccList);
                        break;
                    case MAILIMF_FIELD_SUBJECT:
                        printf("\n");
                        //display_subject(f->fld_data.fld_subject);
                        binn_object_set_str(mailReturn, "Subject",f->fld_data.fld_subject->sbj_value);
                        //printf("\n");
                        break;
                    case MAILIMF_FIELD_MESSAGE_ID:
                        //printf("Message-ID: %s\n", f->fld_data.fld_message_id->mid_value);
                        binn_object_set_str(mailReturn, "Message-id", f->fld_data.fld_message_id->mid_value);
                        break;
                    case MAILIMF_FIELD_OPTIONAL_FIELD:
                        //printf("%s : %s\n",f->fld_data.fld_optional_field->fld_name, f->fld_data.fld_optional_field->fld_value);
                        binn_object_set_str(mailReturn, f->fld_data.fld_optional_field->fld_name, f->fld_data.fld_optional_field->fld_value);
                }
            }
        }
    }
    //printf("Body : %s", mime->mm_data.mm_message.mm_msg_mime->mm_body->dt_data.dt_filename);
    binn_object_set_str(mailReturn, "Body", mime->mm_data.mm_message.mm_msg_mime->mm_body->dt_data.dt_filename);
    mailmime_free(mime);
    free(data);
    return mailReturn;
}

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct upload_status *upload_ctx = (struct upload_status *)userp;
    const char *data;

    if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
        return 0;
    }

    data = payload_text[upload_ctx->lines_read];

    if(data) {
        size_t len = strlen(data);
        memcpy(ptr, data, len);
        upload_ctx->lines_read++;

        return len;
    }

    return 0;
}

// TODO: add the date header and maybe a name before each header
int sendmail(char* destination, char* source, char* subject, char* nonceAES, char* IDused, char* content, char* signature, char* cipher, char *email, char *password){
    //payload_text = malloc(9*sizeof(char*)); // 52Kb for the moment
    //memset(payload_text, 0, 9*sizeof(char*));
    //strcat(payload_text, "Data : ");
    //strcat(payload_text, time(0));
    char * to_text = malloc(100); // 52Kb for the moment
    memset(to_text, 0, 100);
    strcat(to_text, "To : ");
    strcat(to_text, destination);
    strcat(to_text, "\r\n");
    payload_text[0] = to_text;

    char * from_text = malloc(100); // 52Kb for the moment
    memset(from_text, 0, 100);
    strcat(from_text, "From : ");
    strcat(from_text, source);
    strcat(from_text, "\r\n");
    payload_text[1] = from_text;

    char * subject_text = malloc(100); // 52Kb for the moment
    memset(subject_text, 0, 100);
    strcat(subject_text, "Subject : ");
    strcat(subject_text, subject);
    strcat(subject_text, "\r\n");
    payload_text[2] = subject_text;

    char * aesNonce_text = malloc(100); // 52Kb for the moment
    memset(aesNonce_text, 0, 100);
    strcat(aesNonce_text, "X-AES-NONCE : ");
    strcat(aesNonce_text, nonceAES);
    strcat(aesNonce_text, "\r\n");
    payload_text[3] = aesNonce_text;

    char * fullID = malloc(100); // 52Kb for the moment
    memset(fullID, 0, 100);
    strcat(fullID, "X-FULL-ID-USED : ");
    strcat(fullID, IDused);
    strcat(fullID, "\r\n");
    payload_text[4] = fullID;

    char * signature_text = malloc(300); // 52Kb for the moment
    memset(signature_text, 0, 300);
    strcat(signature_text, "X-SIGNATURE-B64 : ");
    strcat(signature_text, signature);
    strcat(signature_text, "\r\n");
    payload_text[5] = signature_text;

    char * cipher_text = malloc(1000); // 52Kb for the moment
    memset(cipher_text, 0, 1000);
    strcat(cipher_text, "X-CIPHER-B64 : ");
    strcat(cipher_text, cipher);
    strcat(cipher_text, "\r\n");
    payload_text[6] = cipher_text;

    char * before_body = malloc(50); // 52Kb for the moment
    memset(before_body, 0, 50);
    strcat(before_body, "\r\n");
    payload_text[7] = before_body;

    char * bodyEnd = malloc(100); // 52Kb for the moment
    memset(bodyEnd, 0, 100);
    strcat(bodyEnd, content);
    payload_text[8] = bodyEnd;

    char * nullTerminated = malloc(1); // 52Kb for the moment
    memset(nullTerminated, 0, 1);
    payload_text[9] = nullTerminated;

    CURL *curl;
    CURLcode res = CURLE_OK;
    struct curl_slist *recipients = NULL;
    struct upload_status upload_ctx;

    upload_ctx.lines_read = 0;

    curl = curl_easy_init();
    if(curl) {
        /* Set username and password */
        curl_easy_setopt(curl, CURLOPT_USERNAME, email);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password);

        /* This is the URL for your mailserver. Note the use of port 587 here,
         * instead of the normal SMTP port (25). Port 587 is commonly used for
         * secure mail submission (see RFC4403), but you should use whatever
         * matches your server configuration. */
        curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");

        /* In this example, we'll start with a plain text connection, and upgrade
         * to Transport Layer Security (TLS) using the STARTTLS command. Be careful
         * of using CURLUSESSL_TRY here, because if TLS upgrade fails, the transfer
         * will continue anyway - see the security discussion in the libcurl
         * tutorial for more details. */
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

        /* If your server doesn't have a valid certificate, then you can disable
         * part of the Transport Layer Security protection by setting the
         * CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST options to 0 (false).
         *   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
         *   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
         * That is, in general, a bad idea. It is still better than sending your
         * authentication details in plain text though.  Instead, you should get
         * the issuer certificate (or the host certificate if the certificate is
         * self-signed) and add it to the set of certificates that are known to
         * libcurl using CURLOPT_CAINFO and/or CURLOPT_CAPATH. See docs/SSLCERTS
         * for more information. */
        //curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/certificate.pem");

        /* Note that this option isn't strictly required, omitting it will result
         * in libcurl sending the MAIL FROM command with empty sender data. All
         * autoresponses should have an empty reverse-path, and should be directed
         * to the address in the reverse-path which triggered them. Otherwise,
         * they could cause an endless loop. See RFC 5321 Section 4.5.5 for more
         * details.
         */
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, source);

        /* Add two recipients, in this particular case they correspond to the
         * To: and Cc: addressees in the header, but they could be any kind of
         * recipient. */
        recipients = curl_slist_append(recipients, destination);
        //recipients = curl_slist_append(recipients, CC);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        /* We're using a callback function to specify the payload (the headers and
         * body of the message). You could just use the CURLOPT_READDATA option to
         * specify a FILE pointer to read from. */
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        /* Since the traffic will be encrypted, it is very useful to turn on debug
         * information within libcurl to see what is happening during the transfer.
         */
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

        /* Send the message */
        res = curl_easy_perform(curl);

        /* Check for errors */
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* Free the list of recipients */
        curl_slist_free_all(recipients);

        /* Always cleanup */
        curl_easy_cleanup(curl);
    }
    free(nullTerminated);
    free(bodyEnd);
    free(before_body);
    free(cipher_text);
    free(signature_text);free(fullID);
    free(aesNonce_text);
    free(subject_text);
    free(from_text);
    free(to_text);

    return (int)res;
}
static void check_error(int r, char * msg)
{
    if (r == MAILIMAP_NO_ERROR)
        return;
    if (r == MAILIMAP_NO_ERROR_AUTHENTICATED)
        return;
    if (r == MAILIMAP_NO_ERROR_NON_AUTHENTICATED)
        return;

    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

static char * get_msg_att_msg_content(struct mailimap_msg_att * msg_att, size_t * p_msg_size)
{
    clistiter * cur;

    /* iterate on each result of one given message */
    for(cur = clist_begin(msg_att->att_list) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att_item * item;

        item = clist_content(cur);
        if (item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
            continue;
        }

        if (item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_BODY_SECTION) {
            continue;
        }

        * p_msg_size = item->att_data.att_static->att_data.att_body_section->sec_length;
        return item->att_data.att_static->att_data.att_body_section->sec_body_part;
    }

    return NULL;
}

static char * get_msg_content(clist * fetch_result, size_t * p_msg_size)
{
    clistiter * cur;

    /* for each message (there will probably be only one message) */
    for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att * msg_att;
        size_t msg_size;
        char * msg_content;

        msg_att = clist_content(cur);
        msg_content = get_msg_att_msg_content(msg_att, &msg_size);
        if (msg_content == NULL) {
            continue;
        }

        * p_msg_size = msg_size;
        return msg_content;
    }

    return NULL;
}

static void fetch_msg(struct mailimap * imap, uint32_t uid)
{
    struct mailimap_set * set;
    struct mailimap_section * section;
    char filename[512];
    size_t msg_len;
    char * msg_content;
    FILE * f;
    struct mailimap_fetch_type * fetch_type;
    struct mailimap_fetch_att * fetch_att;
    int r;
    clist * fetch_result;
    struct stat stat_info;

    snprintf(filename, sizeof(filename), "download/%u.eml", (unsigned int) uid);
    r = stat(filename, &stat_info);
    if (r == 0) {
        // already cached
        printf("%u is already fetched\n", (unsigned int) uid);
        return;
    }

    set = mailimap_set_new_single(uid);
    fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
    section = mailimap_section_new(NULL);
    fetch_att = mailimap_fetch_att_new_body_peek_section(section);
    mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

    r = mailimap_uid_fetch(imap, set, fetch_type, &fetch_result);
    check_error(r, "could not fetch");
    printf("fetch %u\n", (unsigned int) uid);

    msg_content = get_msg_content(fetch_result, &msg_len);
    if (msg_content == NULL) {
        fprintf(stderr, "no content\n");
        mailimap_fetch_list_free(fetch_result);
        return;
    }

    f = fopen(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "could not write\n");
        mailimap_fetch_list_free(fetch_result);
        return;
    }

    fwrite(msg_content, 1, msg_len, f);
    fclose(f);

    printf("%u has been fetched\n", (unsigned int) uid);

    mailimap_fetch_list_free(fetch_result);
}

static uint32_t get_uid(struct mailimap_msg_att * msg_att)
{
    clistiter * cur;

    /* iterate on each result of one given message */
    for(cur = clist_begin(msg_att->att_list) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att_item * item;

        item = clist_content(cur);
        if (item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
            continue;
        }

        if (item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_UID) {
            continue;
        }

        return item->att_data.att_static->att_data.att_uid;
    }

    return 0;
}

static void fetch_messages(struct mailimap * imap)
{
    struct mailimap_set * set;
    struct mailimap_fetch_type * fetch_type;
    struct mailimap_fetch_att * fetch_att;
    clist * fetch_result;
    clistiter * cur;
    int r;

    /* as improvement UIDVALIDITY should be read and the message cache should be cleaned
       if the UIDVALIDITY is not the same */

    set = mailimap_set_new_interval(1, 0); /* fetch in interval 1:* */
    /*
    char *test = malloc(100);
    memset(test, 0, 100);
    strcat(test, "SEARCH SINCE \"");
    time_t rawtime = time(NULL);
    rawtime -= 86400;
    char* timeFormat = malloc(50);
    memset(timeFormat, 0, 50);
    struct tm *ptm = localtime(&rawtime);
    strftime(timeFormat, 50, "%d-%b-%Y", ptm);
    strcat(test, timeFormat);
    strcat(test, "\"\r\n");
    r = mailimap_custom_command(imap, "SEARCH NEW\r\n");
    check_error(r, "Could not compute last emails");
    printf("Response to search : %s", imap->imap_response);
     */

    fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
    fetch_att = mailimap_fetch_att_new_uid();
    mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

    r = mailimap_fetch(imap, set, fetch_type, &fetch_result);
    check_error(r, "could not fetch");

    /* for each message */
    for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att * msg_att;
        uint32_t uid;

        msg_att = clist_content(cur);
        uid = get_uid(msg_att);
        if (uid == 0)
            continue;

        fetch_msg(imap, uid);
    }

    mailimap_fetch_list_free(fetch_result);
}
int checkmail(char* email, char *password){
    struct mailimap * imap;
    int r;

    mkdir("download", 0700);

    imap = mailimap_new(0, NULL);
    r = mailimap_ssl_connect(imap, "imap.gmail.com", 993);
    fprintf(stderr, "connect: %i\n", r);
    check_error(r, "could not connect to server");

    r = mailimap_login(imap, email, password);
    check_error(r, "could not login");

    r = mailimap_select(imap, "INBOX");
    check_error(r, "could not select INBOX");

    fetch_messages(imap);

    mailimap_logout(imap);
    mailimap_free(imap);
}

int checkIfParamsExistAlready(char* userID){
    FILE *file;
    file = fopen(userID, "r");
    if (file){
        fclose(file);
        return 1;
    }
    return 0;
}

void getParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
               bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID){
    FILE *savedParams;
    binn* paramsObjBinn;
    savedParams = fopen(userID, "rb");
    unsigned char *decryptedParams;
    if(savedParams) {
        unsigned char aesk[crypto_secretbox_KEYBYTES];
        printf("Pleas give us the password to decrypt your personal data : \n");
        // Max size of an email address
        char* userPassword = malloc(320);
        fgets(userPassword, 320, stdin);
        userPassword[strlen(userPassword)-1] = '\x00';
        /*
        printf("Please give us the salt :\n");
        char* saltEntered = malloc(50);
        fgets(saltEntered, 50, stdin);
        saltEntered[strlen(saltEntered)-1] = '\x00';

         */
        fseek(savedParams, 0, SEEK_END);
        long fileSize = ftell(savedParams);
        fseek(savedParams, 0, SEEK_SET);

        char *paramsB64 = malloc(fileSize);
        fread(paramsB64, fileSize, 1, savedParams);
        fclose(savedParams);

        size_t saltSize;
        binn *objParams;
        objParams = binn_open(paramsB64);
        char *saltSaved = binn_object_str(objParams, "salt");
        unsigned char *salt = base64_decode(saltSaved, strlen(saltSaved), &saltSize);

        size_t outLen;
        char *encryptedParams = binn_object_str(objParams, "b64Encrypted");
        unsigned char *decodedParams = base64_decode(encryptedParams, strlen(encryptedParams), &outLen);

        size_t outLenNonce;
        char *nonceB64 = binn_object_str(objParams, "nonce");
        unsigned char *nonceDecoded = base64_decode(nonceB64, strlen(nonceB64), &outLenNonce);

        if (crypto_pwhash
                    (aesk, sizeof aesk, userPassword, strlen(userPassword), salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
            printf("Not enough memory");
            /* out of memory */
        }


        /*
        printf("Please give us the nonce :\n");
        char* nonceEntered = malloc(50);
        fgets(nonceEntered, 50, stdin);
        nonceEntered[strlen(nonceEntered)-1] = '\x00';
         */


        //free(nonceEntered);

        decryptedParams = malloc(outLen);
        decrypt_message(decryptedParams, decodedParams, nonceDecoded, aesk, outLen, NULL,0);
        free(nonceDecoded);
        free(decodedParams);
        free(salt);

        paramsObjBinn = binn_open(decryptedParams);
    } else {
        printf("Failed to open a file to save params\n");
        return;
    }

    binn *obj;
    obj = binn_list_object(paramsObjBinn, 1);
    deserialize_MPKE(obj, mpkSession);

    obj = binn_list_object(paramsObjBinn, 2);
    deserialize_MPKS(obj, mpkSignature);

    int size = 0;
    void *bnBin = NULL;
    bnBin = binn_list_blob(paramsObjBinn,3, &size);
    bn_read_bin(*encryption_secret, bnBin, size);

    bnBin = binn_list_blob(paramsObjBinn,4, &size);
    bn_read_bin(*signature_secret, bnBin, size);

    obj = binn_list_object(paramsObjBinn, 5);
    deserialize_PKE(obj, encryptionPk);

    obj = binn_list_object(paramsObjBinn, 6);
    deserialize_PKS(obj, signaturePk);

    char* userSaved = binn_list_str(paramsObjBinn, 7);
    strcpy(userID, userSaved);
    binn_free(paramsObjBinn);
    free(decryptedParams);
}

void saveParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
                bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID){
    binn* list;
    list = binn_list();
    binn *obj;
    obj = binn_object();
    serialize_MPKE(obj, *mpkSession);
    binn_list_add_object(list, obj);
    binn_free(obj);

    obj = binn_object();
    serialize_MPKS(obj, *mpkSignature);
    binn_list_add_object(list, obj);
    binn_free(obj);

    obj = binn_object();
    int size = bn_size_bin(*encryption_secret);
    uint8_t *bin = malloc(size);
    bn_write_bin(bin, size, *encryption_secret);
    binn_list_add_blob(list, bin, size);
    binn_free(obj);
    free(bin);

    obj = binn_object();
    size = bn_size_bin(*signature_secret);
    bin = malloc(size);
    bn_write_bin(bin, size, *signature_secret);
    binn_list_add_blob(list, bin, size);
    binn_free(obj);
    free(bin);

    obj = binn_object();
    serialize_PKE(obj, *encryptionPk);
    binn_list_add_object(list, obj);
    binn_free(obj);

    obj = binn_object();
    serialize_PKS(obj, *signaturePk);
    binn_list_add_object(list, obj);
    binn_free(obj);

    binn_list_add_str(list, userID);

    FILE *savingParams;
    savingParams = fopen(userID, "wb");
    if(savingParams){
        size_t outLen;
        unsigned char *m = binn_ptr(list);
        unsigned long m_len = binn_size(list);
        unsigned char aesk[crypto_secretbox_KEYBYTES];
        printf("In order to securely save your personal parameters we need you to provide a (strong) password for encrypting your personal data : \n");
        // Max size of an email address
        char* userPassword = malloc(320);
        fgets(userPassword, 320, stdin);
        userPassword[strlen(userPassword)-1] = '\x00';

        //TODO : store this
        unsigned char salt[crypto_pwhash_SALTBYTES];
        printf("We give the salt and need to store it for future use :\n");
        randombytes_buf(salt, sizeof salt);
        size_t sizeB64Salt;
        unsigned char *b64Salt = base64_encode(salt, crypto_pwhash_SALTBYTES, &sizeB64Salt);
        printf("%s\n", b64Salt);


        if (crypto_pwhash
                    (aesk, sizeof aesk, userPassword, strlen(userPassword), salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
            printf("Not enough memory");
            /* out of memory */
        }
        unsigned char nonceAES[crypto_aead_aes256gcm_NPUBBYTES];
        unsigned long long cipher_len;
        unsigned char ciphertextAES[m_len + crypto_aead_aes256gcm_ABYTES];
        encrypt_message(m, aesk, nonceAES, ciphertextAES, &cipher_len, &m_len, NULL, 0);
        printf("We give the nonce and need to store it for future use :\n");
        size_t outLenB64Nonce;
        unsigned char *b64nonce = base64_encode(nonceAES, crypto_aead_aes256gcm_NPUBBYTES, &outLenB64Nonce);
        printf("%s\n", b64nonce);


        size_t b64EncryptedLen;
        unsigned char *encryptedContent = base64_encode(ciphertextAES, cipher_len, &b64EncryptedLen);
        binn *savedParamsBinn;
        savedParamsBinn = binn_object();
        binn_object_set_str(savedParamsBinn, "b64Encrypted", encryptedContent);
        binn_object_set_str(savedParamsBinn, "nonce", b64nonce);
        binn_object_set_str(savedParamsBinn, "salt", b64Salt);
        size_t test = fwrite(binn_ptr(savedParamsBinn), binn_size(savedParamsBinn), 1, savingParams);
        if(test > 0){
            printf("Encypted params saved\n");
        } else {
            printf("Failed to save Params\n");
        }
        free(b64nonce);
        free(b64Salt);
        free(userPassword);
        free(encryptedContent);
        fclose(savingParams);
        binn_free(savedParamsBinn);
    } else {
        printf("Failed to open a file to save params\n");
    }
    binn_free(list);
}

void generateAndSendParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
        bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID){

    int sock = connectToKGC();

    binn *objToSend;
    objToSend = binn_object();
    binn_object_set_str(objToSend, "opCode", "HELO");
    binn_object_set_str(objToSend, "ID", userID);
    send(sock , binn_ptr(objToSend) , binn_size(objToSend) , 0 );
    binn_free(objToSend);
    printf("Retrieving all public params from KGC\n");

    unsigned char buf[52000];  //52Kb fixed-size buffer
    recvAll(sock, buf, 52000);

    binn *list;
    list = binn_open(buf);
    binn *mpks, *mpke;
    mpks = binn_list_object(list, 1);
    mpke = binn_list_object(list, 2);
    deserialize_MPKS(mpks, mpkSignature);
    deserialize_MPKE(mpke, mpkSession);
    binn_free(list);

    printf("Generating and saving secret values and public keys\n");
    // Now we can go for user's private keys (encrypting and signing)

    setSec(encryption_secret);
    setSecSig(signature_secret);
    // -------------------------------------------------------------
    // Private keys set for Alice

    // Now we can go to set Public keys for both signing and encrypting

    setPub(*encryption_secret, *mpkSession, encryptionPk);
    setPubSig(*signature_secret, *mpkSignature, signaturePk);

    sock = connectToKGC();

    binn* pkBinnObj;
    pkBinnObj = binn_list();
    binn* encryption_PkBinnObj, *signature_PkBinnObj;
    encryption_PkBinnObj = binn_object();
    signature_PkBinnObj = binn_object();
    serialize_PKE(encryption_PkBinnObj, *encryptionPk);
    serialize_PKS(signature_PkBinnObj, *signaturePk);
    binn_list_add_object(pkBinnObj, encryption_PkBinnObj);
    binn_list_add_object(pkBinnObj, signature_PkBinnObj);
    binn_free(encryption_PkBinnObj);
    binn_free(signature_PkBinnObj);

    binn* packetSendingPK;
    packetSendingPK = binn_object();
    binn_object_set_str(packetSendingPK, "opCode", "PK");
    binn_object_set_str(packetSendingPK, "ID", userID);

    size_t outLen;
    unsigned char* b64Payload = base64_encode(binn_ptr(pkBinnObj), binn_size(pkBinnObj), &outLen);
    printf("PK obj : %s\n", b64Payload);
    binn_object_set_str(packetSendingPK, "PK", b64Payload);
    // TODO : Vérifi si ok
    free(b64Payload);

    int sizeSent = send(sock, binn_ptr(packetSendingPK), binn_size(packetSendingPK), 0);
    printf("Size of PK : %d\n", sizeSent);
    binn_free(pkBinnObj);
    binn_free(packetSendingPK);
}


int connectToKGC(){
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    return sock;
}


int main() {
    if(core_init() == RLC_ERR){
        printf("RELIC INIT ERROR !\n");
    }
    if(sodium_init() < 0) {
        printf("LIBSODIUM INIT ERROR !\n");
    }
    if(pc_param_set_any() == RLC_OK){
        pc_param_print();
        printf("Security : %d\n", pc_param_level());

        // MPK struct, Master Public Key structure to store
        encryption_mpk mpkSession;
        signature_mpk mpkSignature;
        bn_t encryption_secret;
        bn_null(encryption_secret)
        bn_new(encryption_secret)
        bn_t signature_secret;
        bn_null(signature_secret)
        bn_new(signature_secret)
        encryption_pk encryptionPk;
        signature_pk signaturePk;

        // Max size of an email address
        char* userID = malloc(320);
        printf("What's your email (Gmail) ?\n");
        fgets(userID, 320, stdin);
        userID[strlen(userID)-1] = '\x00';

        // Max size of an email address
        char* password = malloc(320);
        printf("What's your password (Gmail) ?\n");
        fgets(password, 320, stdin);
        password[strlen(password)-1] = '\x00';

        int existingParams = checkIfParamsExistAlready(userID);
        if(existingParams == 1){
            //TODO Recup params
            printf("Params found on disk, retrieving these\n");
            getParams(&mpkSession, &mpkSignature, &encryption_secret,
                      &signature_secret, &encryptionPk, &signaturePk, userID);
        }
        // If there are no params saved we can go for a full generation
        else {
            generateAndSendParams(&mpkSession, &mpkSignature, &encryption_secret, &signature_secret, &encryptionPk, &signaturePk, userID);
            saveParams(&mpkSession, &mpkSignature, &encryption_secret, &signature_secret, &encryptionPk, &signaturePk, userID);
        }
        printf("Do you want to send an email (0) or decrypt one (1) ?\n");
        int sendOrDecryptUser;
        char* charUserChoice = malloc(4);
        fgets(charUserChoice, 4, stdin);
        charUserChoice[strlen(charUserChoice)-1] = '\x00';

        sendOrDecryptUser = strtol(charUserChoice, NULL, 10);
        // If we want to send an email
        if(sendOrDecryptUser == 0) {
            // At this point we're sure that params are full, by generating them or retrieving from the user disk
            // So now we can ask the user about the email he want to send
            printf("Now params are loaded, please enter the destination address of the email :\n");
            char *destinationID = malloc(320);
            fgets(destinationID, 320, stdin);
            destinationID[strlen(destinationID)-1] = '\x00';

            // Max size seems to be like more than 130 chars but some email clients truncate to 130
            printf("What's the subject :\n");
            char *subject = malloc(130);
            fgets(subject, 130, stdin);
            subject[strlen(subject)-1] = '\x00';

            printf("Message :\n");
            //arbitrary size
            char *message = malloc(10000);
            fgets(message, 10000, stdin);
            message[strlen(message)-1] = '\x00';
            printf("\n\nHere is a summary of the mail that will be sent, are you ok (yes/no) ?\n");
            printf("From : %s\n", userID);
            printf("To : %s\n", destinationID);
            printf("Subject : %s\n", subject);
            printf("Content : %s\n", message);

            char *userChoice = malloc(4);
            fgets(userChoice, 4, stdin);
            userChoice[strlen(userChoice)-1] = '\x00';
            if (strcmp(userChoice, "no") == 0) {
                printf("Not implemented yet");
                return -1;
            }
            free(userChoice);

            //TODO : do this for all destination, or implement something on te KGC to send all the asked public keys
            int sock = connectToKGC();
            binn *getPKBinnObj;
            getPKBinnObj = binn_object();
            binn_object_set_str(getPKBinnObj, "opCode", "GPE");
            binn_object_set_str(getPKBinnObj, "ID", destinationID);
            send(sock, binn_ptr(getPKBinnObj), binn_size(getPKBinnObj), 0);
            binn_free(getPKBinnObj);

            char bufferGPE[512] = {0};
            int testSize = recv(sock, bufferGPE, 512, 0);
            // printf("%s\n", bufferGPE);
            encryption_pk encryption_destinationPk;
            size_t out_len_test;
            unsigned char *decodedTest = base64_decode(bufferGPE, testSize, &out_len_test);
            deserialize_PKE(decodedTest, &encryption_destinationPk);
            free(decodedTest);

            // The other user takes ID of the destination and PK to encrypt his message
            // With the final version we will need to append a timestamp on the ID

            gt_t AESK;gt_null(AESK);gt_new(AESK);
            // For now we take m (AES Key) randomly from Gt
            gt_rand(AESK);

            unsigned char aesk[crypto_secretbox_KEYBYTES];
            get_key(aesk, AESK);

            unsigned char nonceAES[crypto_aead_aes256gcm_NPUBBYTES];
            size_t m_len = strlen(message);
            unsigned long long cipher_len;
            unsigned char ciphertextAES[m_len + crypto_aead_aes256gcm_ABYTES];
            size_t authenticatedDataSize = strlen(userID) + strlen(destinationID) + strlen(subject) + 1;
            unsigned char *authenticatedData = malloc(authenticatedDataSize);
            memset(authenticatedData, 0, authenticatedDataSize);
            strcpy(authenticatedData, userID);
            strcat(authenticatedData, destinationID);
            strcat(authenticatedData, subject);
            encrypt_message(message, aesk, nonceAES, ciphertextAES, &cipher_len, &m_len, authenticatedData, authenticatedDataSize);
            unsigned char *ciphertextB64 = base64_encode(ciphertextAES, cipher_len, NULL);
            printf("Encrypted message : %s\n", ciphertextB64);

            unsigned char *nonceAesB64 = base64_encode(nonceAES, crypto_aead_aes256gcm_NPUBBYTES, NULL);
            printf("Nonce message : %s\n", nonceAesB64);


            // Encryption of the AES Key with the Public key of the destination
            cipher c;
            //TODO : add timestamp
            encrypt(AESK, encryption_destinationPk, destinationID, mpkSession, &c);
            // TODO print base64 of cipher for decrypt
            binn *cipherBinnObect;
            cipherBinnObect = binn_object();
            serialize_Cipher(cipherBinnObect, c);
            unsigned char *cipherB64 = base64_encode(binn_ptr(cipherBinnObect), binn_size(cipherBinnObect), NULL);
            printf("Cipher base64 : %s\n", cipherB64);

            binn_free(cipherBinnObect);

            // For the signature we need our PPK
            signature_ppk signature_senderPpk;
            sock = connectToKGC();
            char bufferPPK[1024] = {0};
            binn *signatureExtractionSenderBinnObj;
            signatureExtractionSenderBinnObj = binn_object();
            binn_object_set_str(signatureExtractionSenderBinnObj, "opCode", "SE");
            binn_object_set_str(signatureExtractionSenderBinnObj, "ID", userID);
            send(sock, binn_ptr(signatureExtractionSenderBinnObj), binn_size(signatureExtractionSenderBinnObj), 0);
            binn_free(signatureExtractionSenderBinnObj);

            read(sock, bufferPPK, 1024);
            deserialize_PPKS(bufferPPK, &signature_senderPpk);

            // Computes Secret User Keys for Signature
            signature_sk signature_senderSk;
            setPrivSig(signature_secret, signature_senderPpk, mpkSignature, userID, &signature_senderSk);

            // Computes the message to sign, so the cipher struct
            int c0size = gt_size_bin(c.c0, 1);
            int c1Size = g1_size_bin(c.c1, 1);
            int c2Size = g2_size_bin(c.c2, 1);
            int c3Size = g2_size_bin(c.c3, 1);
            uint8_t mSig[c0size + c1Size + c2Size + c3Size];
            gt_write_bin(mSig, c0size, c.c0, 1);
            g1_write_bin(&mSig[c0size], c1Size, c.c1, 1);
            g2_write_bin(&mSig[c0size + c1Size], c2Size, c.c2, 1);
            g2_write_bin(&mSig[c0size + c1Size + c2Size], c3Size, c.c3, 1);

            // Structure of an signature
            signature s;
            // We can sign using our private keys and public ones
            sign(mSig, signature_senderSk, signaturePk, userID, mpkSignature, &s);
            // TODO print base64 of signature for decrypt
            binn *signatureObjBinn;
            signatureObjBinn = binn_object();
            serialize_Signature(signatureObjBinn, s);
            unsigned char *b64signatureObjBinn = base64_encode(binn_ptr(signatureObjBinn), binn_size(signatureObjBinn), NULL);
            printf("Signature (base64) : %s\n", b64signatureObjBinn);

            // TODO add timestamp sendmail
            sendmail(destinationID, userID, subject, nonceAesB64, userID, ciphertextB64, b64signatureObjBinn, cipherB64, userID, password);
            free(nonceAesB64);
            free(ciphertextB64);
            free(b64signatureObjBinn);
            free(cipherB64);
            binn_free(signatureObjBinn);

            //TODO : Construct a structure of the email to be able to send easily

            // ----------------------------------------------------------------------
            // Now the message is encrypted and authentified with an AES Key and the key is encrypted and signed using CLPKC
            // ----------------------------------------------------------------------

            free(message);
            free(subject);
            free(destinationID);
        }
        // If we want to decrypt an email
        else {
            checkmail(userID, password);

            DIR *dir;
            struct dirent *ent;
            if ((dir = opendir ("download")) != NULL) {
                /* print all the files and directories within directory */
                while ((ent = readdir (dir)) != NULL) {
                    printf ("%s\n", ent->d_name);
                }
                closedir (dir);
            } else {
                /* could not open directory */
                perror ("");
                return EXIT_FAILURE;
            }
            printf("Choose a file to parse (filename): \n");
            char *fileChoice = malloc(256);
            memset(fileChoice, 0, 256);
            fgets(fileChoice, 256, stdin);
            fileChoice[strlen(fileChoice)-1] = '\x00';
            /*
            int testNumber = strtol(fileChoice, NULL, 10);
            char *filename = malloc(256);
            memset(filename, 0, 256);
            if ((dir = opendir ("download")) != NULL) {
                for(int j = 0; j < testNumber;++j) {
                    ent = readdir (dir);
                    printf ("%s\n", ent->d_name);

                }
                strcpy(filename, ent->d_name);
                closedir (dir);
            } else {

                perror ("");
                return EXIT_FAILURE;
            }
            */
            printf("filename  : %s", fileChoice);
            binn* emailObj = parseEmail(fileChoice);

            char *sourceAddress = binn_object_str(emailObj, "From");
            char *b64Signature = binn_object_str(emailObj, "X-SIGNATURE-B64");
            char *b64Cipher = binn_object_str(emailObj, "X-CIPHER-B64");
            char *b64Encrypted = binn_object_str(emailObj, "Body");
            char *b64Nonce = binn_object_str(emailObj, "X-AES-NONCE");
            char *subject = binn_object_str(emailObj, "Subject");
            // TODO : timestamp
            char *fullID = binn_object_str(emailObj, "X-TIMESTAMP-USED");
            if(b64Signature == NULL || b64Cipher == NULL || b64Encrypted == NULL || b64Nonce == NULL){
                printf("I cannot parse the email, it's not an email written by my POC\n");
                exit(EXIT_FAILURE);
            }

            signature s;
            size_t outLen;
            unsigned char *signatureBinn = base64_decode(b64Signature, strlen(b64Signature), &outLen);
            deserialize_Signature(signatureBinn, &s);
            free(signatureBinn);
            cipher c;
            unsigned char *cipherBinn = base64_decode(b64Cipher, strlen(b64Cipher),&outLen);
            deserialize_Cipher(cipherBinn, &c);
            free(cipherBinn);

            // Computes the message to sign, so the cipher struct
            int c0size = gt_size_bin(c.c0, 1);
            int c1Size = g1_size_bin(c.c1, 1);
            int c2Size = g2_size_bin(c.c2, 1);
            int c3Size = g2_size_bin(c.c3, 1);
            uint8_t mSig[c0size + c1Size + c2Size + c3Size];
            gt_write_bin(mSig, c0size, c.c0, 1);
            g1_write_bin(&mSig[c0size], c1Size, c.c1, 1);
            g2_write_bin(&mSig[c0size + c1Size], c2Size, c.c2, 1);
            g2_write_bin(&mSig[c0size + c1Size + c2Size], c3Size, c.c3, 1);

            int sock = connectToKGC();
            binn *getPKBinnObj;
            getPKBinnObj = binn_object();
            binn_object_set_str(getPKBinnObj, "opCode", "GPS");
            binn_object_set_str(getPKBinnObj, "ID", sourceAddress);
            send(sock, binn_ptr(getPKBinnObj), binn_size(getPKBinnObj), 0);
            binn_free(getPKBinnObj);

            char bufferGPS[512] = {0};
            int testSize = recv(sock, bufferGPS, 512, 0);
            // printf("%s\n", bufferGPE);
            signature_pk signature_sourcePK;
            size_t out_len_test;
            unsigned char *signature_sourcePKBin = base64_decode(bufferGPS, testSize, &out_len_test);
            deserialize_PKS(signature_sourcePKBin, &signature_sourcePK);

            // We can go for decrypting and verification
            // We can verify directly with the public keys of the sender
            int test = verify(s, signature_sourcePK, mpkSignature, sourceAddress, mSig);
            printf("\nVerification of the key (0 if correct 1 if not) : %d\n", test);
            // if the verif is ok we can continue, otherwise we can stop here
            if(test == 0) {
                // For this we need our Partial Private Keys with the ID used to encrypt the message
                encryption_ppk PartialKeysBob;

                sock = connectToKGC();

                // TODO add timestamp to extraction
                char bufferPPKE[1024] = {0};
                binn* bobPpk;
                bobPpk = binn_object();
                binn_object_set_str(bobPpk, "opCode", "EE");
                binn_object_set_str(bobPpk, "ID", userID);
                send(sock, binn_ptr(bobPpk), binn_size(bobPpk), 0);
                binn_free(bobPpk);

                read(sock, bufferPPKE, 1024);
                deserialize_PPKE(bufferPPKE, &PartialKeysBob);

                // Computes Secret User Keys
                encryption_sk SecretKeysBob;
                g2_null(SecretKeysBob->s1)
                g2_new(SecretKeysBob->s1)

                g1_null(SecretKeysBob->s2)
                g1_new(SecretKeysBob->s2)
                setPriv(encryption_secret, PartialKeysBob, mpkSession, userID, &SecretKeysBob);

                // We can decrypt now
                gt_t decryptedMessage;
                gt_null(decryptedMessage)
                gt_new(decryptedMessage)
                decrypt(c, SecretKeysBob, encryptionPk, mpkSession, userID, &decryptedMessage);

                char aeskDecrypted[crypto_secretbox_KEYBYTES];
                get_key(aeskDecrypted, decryptedMessage);

                size_t size_cipher;
                unsigned char *ciphertext = base64_decode(b64Encrypted, strlen(b64Encrypted), &size_cipher);
                unsigned char decrypted[size_cipher];
                memset(decrypted, 0, size_cipher);

                // TODO récupérer d'ailleurs
                size_t nonceSize;
                unsigned char* nonceAES = base64_decode(b64Nonce, strlen(b64Nonce), &nonceSize);

                size_t authenticatedDataSize = strlen(sourceAddress) + strlen(userID) + strlen(subject) + 1;
                unsigned char *authenticatedData = malloc(authenticatedDataSize);
                memset(authenticatedData, 0, authenticatedDataSize);
                strcpy(authenticatedData, sourceAddress);
                strcat(authenticatedData, userID);
                strcat(authenticatedData, subject);
                decrypt_message(decrypted, ciphertext, nonceAES, aeskDecrypted, size_cipher, authenticatedData, authenticatedDataSize);
                printf("Decrypted message : %s\n", decrypted);
                free(ciphertext);
                free(nonceAES);
            }

            free(signature_sourcePKBin);
            /*free(b64Nonce);
            free(b64Cipher);
            free(b64Encrypted);
            free(b64Signature);
            free(sourceAddress);
             */
            binn_free(emailObj);
        }
        free(charUserChoice);
        free(userID);
        bn_zero(encryption_secret);
        bn_zero(signature_secret);
        bn_free(encryption_secret)
        bn_free(signature_secret)
    }
    core_clean();
}
