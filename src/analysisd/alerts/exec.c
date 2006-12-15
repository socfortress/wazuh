/* @(#) $Id$ */

/* Copyright (C) 2004-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* Basic e-mailing operations */


#include "shared.h"
#include "rules.h"
#include "alerts.h"
#include "config.h"
#include "active-response.h"

#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "os_execd/execd.h"

#include "eventinfo.h"


/* OS_Exec v0.1 
 */
void OS_Exec(int *execq, int *arq, Eventinfo *lf, active_response *ar)
{
    char exec_msg[OS_SIZE_1024 +1];
    char *ip;
    char *user;


    /* Cleaning the IP */
    if(lf->srcip && (ar->ar_cmd->expect & SRCIP))
    {
        ip = strrchr(lf->srcip, ':');
        if(ip)
        {
            ip++;
        }
        else
        {
            ip = lf->srcip;
        }


        /* Checking if IP is to ignored */
        if(Config.white_list)
        {
            if(OS_IPFoundList(ip, Config.white_list))
            {
                return;
            }
        }
    }
    else
    {
        ip = "-";
    }
   
   
    /* Getting username */
    if(lf->user && (ar->ar_cmd->expect & USERNAME))
    {
        user = lf->user;
    }
    else
    {
        user = "-";
    }


    /* active response on the server. 
     * The response must be here, if the ar->location is set to AS
     * or the ar->location is set to local (REMOTE_AGENT) and the
     * event location is from here.
     */         
    if((ar->location & AS_ONLY) ||
      ((ar->location & REMOTE_AGENT) && (lf->location[0] != '(')) )
    {
        if(!(Config.ar & LOCAL_AR))
            return;
            
        snprintf(exec_msg, OS_SIZE_1024,
                "%s %s %s %d.%ld %s %d",
                ar->name,
                user,
                ip,
                lf->time,
                ftell(_aflog),
                lf->location,
                lf->generated_rule->sigid);

        if(OS_SendUnix(*execq, exec_msg, 0) < 0)
        {
            merror("%s: Error communicating with execd.", ARGV0);
        }
    }
   

    /* Active response to the forwarder */ 
    if((Config.ar & REMOTE_AR) && (lf->location[0] == '('))
    {
        snprintf(exec_msg, OS_SIZE_1024,
                "%s %c%c%c %s %s %s %s %d.%ld %s %d",
                lf->location,
                (ar->location & ALL_AGENTS)?ALL_AGENTS_C:NONE_C,
                (ar->location & REMOTE_AGENT)?REMOTE_AGENT_C:NONE_C,
                (ar->location & SPECIFIC_AGENT)?SPECIFIC_AGENT_C:NONE_C,
                ar->agent_id,
                ar->name,
                user,
                ip,
                lf->time,
                ftell(_aflog),
                lf->location,
                lf->generated_rule->sigid);
       
        if(OS_SendUnix(*arq, exec_msg, 0) < 0)
        {
            merror("%s: Error communicating with ar queue.", ARGV0);
        }
    }
    
    return;
}

/* EOF */
