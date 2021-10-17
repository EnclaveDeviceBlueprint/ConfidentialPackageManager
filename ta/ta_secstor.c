#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_secstor_ta_mgmt.h>
#include "ta_secstor.h"


/* 
 * For now use the psa install funcion. 
 * Change this to write to secure storage ourself so we can do block writes, and don't need the entire TA in memory
 * 
 */
int secstor_install_ta(uint8_t * data, uint32_t size)
{
	TEE_Result res;
	const TEE_UUID uuid = PTA_SECSTOR_TA_MGMT_UUID;
        static TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	uint32_t param_types;
        uint32_t ret_orig;
	TEE_Param params[4];

	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &sess, &ret_orig);
	if (res != TEE_SUCCESS) {
	    EMSG("SDP basic test TA: TEE_OpenTASession() FAILED \n");
	    return res;
	}
	EMSG("Opened session to PTA_SECSTOR_TA_MGMT_UUID");
	

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	
	params[0].memref.buffer = data;
	params[0].memref.size = size;
	
	EMSG("Invoking PTA_SECSTOR_TA_MGMT_BOOTSTRAP command");

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, PTA_SECSTOR_TA_MGMT_BOOTSTRAP, param_types, params, &ret_orig);
	if (res != TEE_SUCCESS) { 
	    EMSG("SPTA_SECSTOR_TA_MGMT_BOOTSTRAP command FAILED %x/%d\n", res, ret_orig);
	}
	
	TEE_CloseTASession(sess);
	
	return res;
}

