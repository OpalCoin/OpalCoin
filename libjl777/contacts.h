//
//  contacts.h
//  telepathy
//
//  Created by jl777 on 10/13/14.
//  Copyright (c) 2014 jl777. MIT License.
//

#ifndef libtest_contacts_h
#define libtest_contacts_h

void create_telepathy_entry(struct contact_info *contact,int32_t sequenceid);

struct contact_info *find_handle(char *handle)
{
    return((struct contact_info *)find_storage(CONTACT_DATA,handle,0));
}

void update_contact_info(struct contact_info *contact)
{
    //printf("update_contact_info %p (%s)\n",contact,contact->handle);
    if ( contact->H.size == 0 )
        contact->H.size = sizeof(*contact);
    update_storage(&SuperNET_dbs[CONTACT_DATA],contact->handle,&contact->H);
}

struct contact_info *find_contact_nxt64bits(uint64_t nxt64bits)
{
    struct contact_info **contacts,*contact,*retcontact = 0;
    int32_t i,numcontacts;
    contacts = (struct contact_info **)copy_all_DBentries(&numcontacts,CONTACT_DATA);
    if ( contacts == 0 )
        return(0);
    for (i=0; i<numcontacts; i++)
    {
        contact = contacts[i];
        if ( contact->nxt64bits == nxt64bits )
        {
            if ( retcontact != 0 )
                free(retcontact);
            retcontact = contact;
        }
        else free(contacts[i]);
    }
    free(contacts);
    if ( retcontact == 0 )
    {
        retcontact = calloc(1,sizeof(*contact));
        retcontact->nxt64bits = nxt64bits;
        expand_nxt64bits(retcontact->handle,nxt64bits);
        update_contact_info(retcontact);
    }
    return(retcontact);
}

uint64_t conv_acctstr(char *acctstr)
{
    uint64_t nxt64bits = 0;
    int32_t len;
    if ( (len= is_decimalstr(acctstr)) > 0 && len < 22 )
        nxt64bits = calc_nxt64bits(acctstr);
    else if ( strncmp("NXT-",acctstr,4) == 0 )
        nxt64bits = conv_rsacctstr(acctstr,0);
    return(nxt64bits);
}

struct contact_info *find_contact(char *contactstr)
{
    uint64_t nxt64bits = 0;
    struct contact_info *contact = 0;
    //printf("_find_contact.(%s)\n",contactstr);
    if ( contactstr == 0 || contactstr[0] == 0 )
        return(0);
    if ( (contact= find_handle(contactstr)) == 0 )
    {
        if ( (nxt64bits= conv_acctstr(contactstr)) != 0 )
            contact = find_contact_nxt64bits(nxt64bits);
    }
    return(contact);
}

struct contact_info **conv_contacts_json(int32_t *nump,cJSON *array)
{
    int32_t i,j,n;
    char contactstr[MAX_JSON_FIELD];
    struct contact_info *contact,**contacts = 0;
    cJSON *item;
    *nump = 0;
    if ( array == 0 || is_cJSON_Array(array) == 0 || (n= cJSON_GetArraySize(array)) <= 0 )
        return(0);
    contacts = calloc(n+1,sizeof(*contacts));
    for (i=j=0; i<n; i++)
    {
        item = cJSON_GetArrayItem(array,i);
        copy_cJSON(contactstr,item);
        if ( contactstr[0] > 0 )
        {
            if ( (contact= find_contact(contactstr)) != 0 )
            {
                if ( contact->nxt64bits != 0 )
                    contacts[j++] = contact;
                //free(contact);
            }
        }
    }
    if ( (*nump= j) == 0 )
    {
        free(contacts);
        contacts = 0;
    }
    return(contacts);
}

char *removecontact(char *previpaddr,char *NXTaddr,char *NXTACCTSECRET,char *sender,char *handle)
{
    int32_t retval;
    char retstr[1024];
    if ( strcmp("myhandle",handle) == 0 )
        return(0);
    if ( (retval= delete_storage(&SuperNET_dbs[CONTACT_DATA],handle)) == 0 )
        sprintf(retstr,"{\"result\":\"handle.(%s) deleted\"}",handle);
    else sprintf(retstr,"{\"error\":\"cant delete handle.(%s)\",\"retval\":%d}",handle,retval);
    printf("REMOVECONTACT.(%s)\n",retstr);
    return(clonestr(retstr));
}

void set_contactstr(char *contactstr,struct contact_info *contact)
{
    char pubkeystr[128],rsacctstr[128];
    rsacctstr[0] = 0;
    conv_rsacctstr(rsacctstr,contact->nxt64bits);
    if ( strcmp(contact->handle,"myhandle") == 0 )
        init_hexbytes_noT(pubkeystr,Global_mp->mypubkey.bytes,sizeof(Global_mp->mypubkey));
    else init_hexbytes_noT(pubkeystr,contact->pubkey.bytes,sizeof(contact->pubkey));
    sprintf(contactstr,"{\"handle\":\"%s\",\"acct\":\"%s\",\"NXT\":\"%llu\",\"pubkey\":\"%s\"}",contact->handle,rsacctstr,(long long)contact->nxt64bits,pubkeystr);
}

char *dispcontact(char *previpaddr,char *NXTaddr,char *NXTACCTSECRET,char *sender,char *handle)
{
    struct contact_info **contacts,*contact;
    int32_t i,numcontacts;
    char retbuf[1024],*retstr = 0;
    retbuf[0] = 0;
    if ( strcmp(handle,"*") == 0 )
    {
        contacts = (struct contact_info **)copy_all_DBentries(&numcontacts,CONTACT_DATA);
        if ( contacts == 0 )
            return(0);
        retstr = clonestr("[");
        for (i=0; i<numcontacts; i++)
        {
            if ( i > 0 )
                strcat(retstr,",");
            set_contactstr(retbuf,contacts[i]);
            retstr = realloc(retstr,strlen(retstr)+strlen(retbuf)+2);
            strcat(retstr,retbuf);
            free(contacts[i]);
        }
        free(contacts);
        strcat(retstr,"]");
    }
    else
    {
        if ( (contact= find_contact(handle)) != 0 )
        {
            set_contactstr(retbuf,contact);
            free(contact);
        }
        else sprintf(retbuf,"{\"error\":\"handle.(%s) doesnt exist\"}",handle);
        retstr = clonestr(retbuf);
    }
    printf("Contact.(%s)\n",retstr);
    return(retstr);
}

void init_Contacts()
{
    char *retstr,NXTaddr[64];
    struct contact_info **contacts,*contact;
    int32_t i,j,n,numcontacts;
    contacts = (struct contact_info **)copy_all_DBentries(&numcontacts,CONTACT_DATA);
    if ( contacts == 0 )
        return;
    for (i=0; i<numcontacts; i++)
        fprintf(stderr,"%s\n",contacts[i]->handle);
    fprintf(stderr,"contacts\n");
    for (i=0; i<numcontacts; i++)
    {
        expand_nxt64bits(NXTaddr,contacts[i]->nxt64bits);
        if ( (retstr= addcontact(contacts[i]->handle,NXTaddr)) != 0 )
        {
            printf("%s\n",retstr);
            free(retstr);
            if ( (contact= find_contact(contacts[i]->handle)) != 0 )
            {
                *contact = *contacts[i];
                printf("lastrecv.%d lastentry.%d\n",contact->lastrecv,contact->lastentry);
                n = (contact->lastrecv + MAX_DROPPED_PACKETS);
                if ( n < (contact->lastentry + 2*MAX_DROPPED_PACKETS) )
                    n = contact->lastentry + 2*MAX_DROPPED_PACKETS;
                for (j=contact->lastrecv; j<n; j++)
                    create_telepathy_entry(contact,j);
                free(contact);
            }
            else printf("error finding (%s) right after adding it!\n",contacts[i]->handle);
        }
        free(contacts[i]);
    }
    printf("finished init contacts\n");
    free(contacts);
}

#endif

