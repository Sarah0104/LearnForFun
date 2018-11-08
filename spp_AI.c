/****************************************************************************
 *
 * Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/
/*
 * spp_AI.c
 *
 * Author:
 *
 * Steven A. Sturges <ssturges@sourcefire.com>
 *
 * Description:
 *
 * This file is part of an example of a dynamically loadable preprocessor.
 *
 * NOTES:
 *
 */

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preproc_lib.h"
#include "sf_dynamic_preprocessor.h"
#include "snort_debug.h"

#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats AIPerfStats;
#endif

#define GENERATOR_EXAMPLE 256
extern DynamicPreprocessorData _dpd;

const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 0;
const int BUILD_VERSION = 0;
const char *PREPROC_NAME = "SF_Dynamic_AI_Preprocessor";

#define AISetup DYNAMIC_PREPROC_SETUP

#define SRC_PORT_MATCH  1
#define SRC_PORT_MATCH_STR "AI_preprocessor: src port match"
#define DST_PORT_MATCH  2
#define DST_PORT_MATCH_STR "AI_preprocessor: dest port match"

typedef struct _AIConfig
{
    u_int16_t portToCheck;

} AIConfig;

tSfPolicyUserContextId ex_config = NULL;
AIConfig *ex_eval_config = NULL;

static void AIInit(struct _SnortConfig *, char *);
static void AIProcess(void *, void *);
static AIConfig * AIParse(char *);
#ifdef SNORT_RELOAD
static void AIReload(struct _SnortConfig *, char *, void **);
static int AIReloadVerify(struct _SnortConfig *, void *);
static int AIReloadSwapPolicyFree(tSfPolicyUserContextId, tSfPolicyId, void *);
static void * AIReloadSwap(struct _SnortConfig *, void *);
static void AIReloadSwapFree(void *);
#endif

void AISetup(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("dynamic_AI", AIInit);
#else
    _dpd.registerPreproc("dynamic_AI", AIInit, AIReload,
            AIReloadVerify, AIReloadSwap, AIReloadSwapFree);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: AI is setup\n"););
}

static void AIInit(struct _SnortConfig *sc, char *args)
{
    AIConfig *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    _dpd.logMsg("AI dynamic preprocessor configuration\n");

    if (ex_config == NULL)
    {
        ex_config = sfPolicyConfigCreate();
        if (ex_config == NULL)
            _dpd.fatalMsg("Could not allocate configuration struct.\n");
    }

    config = AIParse(args);
    sfPolicyUserPolicySet(ex_config, policy_id);
    sfPolicyUserDataSetCurrent(ex_config, config);

    /* Register the preprocessor function, Transport layer, ID 10000 */
    _dpd.addPreproc(sc, AIProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("AI", (void *)&AIPerfStats, 0, _dpd.totalPerfStats, NULL);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: AI is initialized\n"););
}

static AIConfig * AIParse(char *args)
{
    char *arg;
    char *argEnd;
    long port;
    AIConfig *config = (AIConfig *)calloc(1, sizeof(AIConfig));

    if (config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    arg = strtok(args, " \t\n\r");
    if(arg && !strcasecmp("port", arg))
    {
        arg = strtok(NULL, "\t\n\r");
        if (!arg)
        {
            _dpd.fatalMsg("AIPreproc: Missing port\n");
        }

        port = strtol(arg, &argEnd, 10);
        if (port < 0 || port > 65535)
        {
            _dpd.fatalMsg("AIPreproc: Invalid port %d\n", port);
        }
        config->portToCheck = (u_int16_t)port;

        _dpd.logMsg("    Port: %d\n", config->portToCheck);
    }
    else
    {
        _dpd.fatalMsg("AIPreproc: Invalid option %s\n",
            arg?arg:"(missing port)");
    }

    return config;
}

void AIProcess(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    AIConfig *config;
    PROFILE_VARS;

    sfPolicyUserPolicySet(ex_config, _dpd.getNapRuntimePolicy());
    config = (AIConfig *)sfPolicyUserDataGetCurrent(ex_config);
    if (config == NULL)
        return;

    // preconditions - what we registered for
    assert(IsUDP(p) || IsTCP(p));

    PREPROC_PROFILE_START(AIPerfStats);

    if (p->src_port == config->portToCheck)
    {
        /* Source port matched, log alert */
        _dpd.alertAdd(GENERATOR_EXAMPLE, SRC_PORT_MATCH,
                      1, 0, 3, SRC_PORT_MATCH_STR, 0);

        PREPROC_PROFILE_END(AIPerfStats);
        return;
    }

    if (p->dst_port == config->portToCheck)
    {
        /* Destination port matched, log alert */
        _dpd.alertAdd(GENERATOR_EXAMPLE, DST_PORT_MATCH,
                      1, 0, 3, DST_PORT_MATCH_STR, 0);
        PREPROC_PROFILE_END(AIPerfStats);
        return;
    }
    
    PREPROC_PROFILE_END(AIPerfStats);
}

#ifdef SNORT_RELOAD
static void AIReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId ex_swap_config;
    AIConfig *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    _dpd.logMsg("AI dynamic preprocessor configuration\n");

    ex_swap_config = sfPolicyConfigCreate();
    if (ex_swap_config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    config = AIParse(args);
    sfPolicyUserPolicySet(ex_swap_config, policy_id);
    sfPolicyUserDataSetCurrent(ex_swap_config, config);

    /* Register the preprocessor function, Transport layer, ID 10000 */
    _dpd.addPreproc(sc, AIProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

    *new_config = (void *)ex_swap_config;
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: AI is initialized\n"););
}

static int AIReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("Streaming & reassembly must be enabled for AI preprocessor\n");
        return -1;
    }

    return 0;
}

static int AIReloadSwapPolicyFree(tSfPolicyUserContextId config, tSfPolicyId policyId, void *data)
{
    AIConfig *policy_config = (AIConfig *)data;

    sfPolicyUserDataClear(config, policyId);
    free(policy_config);
    return 0;
}

static void * AIReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId ex_swap_config = (tSfPolicyUserContextId)swap_config;
    tSfPolicyUserContextId old_config = ex_config;

    if (ex_swap_config == NULL)
        return NULL;

    ex_config = ex_swap_config;

    return (void *)old_config;
}

static void AIReloadSwapFree(void *data)
{
    tSfPolicyUserContextId config = (tSfPolicyUserContextId)data;

    if (data == NULL)
        return;

    sfPolicyUserDataFreeIterate(config, AIReloadSwapPolicyFree);
    sfPolicyConfigDelete(config);
}
#endif
