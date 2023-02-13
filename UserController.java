
package com.example.controller;


import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import javax.validation.ConstraintViolationException;
import javax.validation.Valid;

import org.apache.commons.lang3.StringUtils;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.extern.slf4j.Slf4j;

/**
 * 
 * This class is to provide user related restful service endpoints.
 *
 */
@SuppressWarnings("deprecation")
@Api(tags = "user", description = " manages user information")
@Slf4j
@RequestMapping("${app.base-endpoint}")
@RestController
public class UserController {

	private static final String MODULE_NAME="User-Management";
	
	@Value("${app.enforce-mfa:true}")
	private boolean enforceMfa;

    @Autowired
    private UserAccountService userAccountService;

    @Autowired
    private VUserJpaRepository vuserJpaRepo;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    
    @Autowired
	private EncryptionService encryptionService;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private PFIntegrationService pfIntegrateService;
    
	@Value("${metadata.default-register-token-validity-days:7}")
	private int daysRegTokenValid;
	
	public static final String ERROR_MSG="Error in registering a new user.";

	/**
	 * Return Cloud configured keys
	 * @param keyId
	 * @return
	 */
	@ApiOperation(value = "returns cloud configured keys", response = Iterable.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request")})
	@LogRequest
	@GetMapping("/vUser/keylist/{id}")
	@AclCheck(value="*:iam:*,*:cloud service configuration:*",page=MODULE_NAME)
	public ResponseEntity<?> getServiceproviderkeyInfo(@ApiParam(name="keyId",value = "key id") @PathVariable("id") String keyId,
			@ApiParam(name="tenantId",value = "tenant id") @RequestParam("tenantId") String tenantId,@ApiParam(name="cloud",value = "type of the cloud") @RequestParam(required = false) String cloud) {
		if (StringUtils.isBlank(keyId) || StringUtils.isBlank(tenantId)) {
			log.error("Bad request : id or tenantId is missing");
			return new ResponseEntity<>(MessageUtil.getMessage("invalidate.request.0002"),
					HttpStatus.BAD_REQUEST);
		}
		Long userId = SecurityContextUtil.getLoginUserRecordId();
		UUID selectedTenantId = UUID.fromString(tenantId);
		log.debug("Inside Controller getServiceproviderkeyInfo ");
		List<ServiceproviderKeyInfoResponseDto> list = fusionUserAccountService
				.findServiceProviderKeys(selectedTenantId, keyId, userId, cloud);
		return new ResponseEntity<>(list, HttpStatus.OK);
	}

	/**
	 * Add/Update Cloud configuration keys.
	 * @param spdto
	 * @return
	 */
	@ApiOperation(value = "add or updates cloud configuration keys", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request")})
	@LogRequest
	@PostMapping("/vUser/addupdatespkey")
	@AclCheck(value = "*:iam:*,*:cloud service configuration:*",page=MODULE_NAME)
	public ResponseEntity<?> addupdateSpkey(@ApiParam(name="body",value = " add/update Cloud configuration keys") @RequestBody ServiceproviderKeyInfoResponseDto spdto) {
		if (spdto.getUrl() == null || spdto.getPublicKey() == null || spdto.getPrivateKey() == null) {
			log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			throw new ConstraintViolationException("Invalid Request Payload", null);
		}
		UUID tenantid = SecurityContextUtil.getLoginUserTenantId();
		log.debug("UserController::logged In tenantid {}", tenantid);
		Long userId = SecurityContextUtil.getLoginUserRecordId();
		log.debug("UserController::adding/updating  for user {}", userId);
		try {
			List<ServiceproviderKeyInfoResponseDto> sodtoList = new ArrayList<>();
			if (spdto.getCloudServiceProvider().equalsIgnoreCase(CSPType.XSTREAM.getValue()))
				spdto.setPrivateKey(encryptionService.encrypt(spdto.getPrivateKey(), tenantid));
			else if (spdto.getCloudServiceProvider().equalsIgnoreCase(CSPType.AZURE.getValue())) {
				// spdto.setSubscriptionid(encryptionService.encrypt(spdto.getSubscriptionid(), tenantid));
			}

			if (StringUtils.isEmpty(spdto.getId()))
				spdto.setId(UUID.randomUUID().toString());

			sodtoList.add(spdto);
			FusionMessage msg = fusionUserAccountService.updateServiceProviderKey(sodtoList, tenantid, userId);
			return new ResponseEntity<>(msg, HttpStatus.OK);
		} catch (Exception e) {
			log.error("Error encountered storing KeyPair for tenantId {}", tenantid);
			log.error("Error: " + e.getMessage() + "\n" + e.getCause());
			throw new AccountServiceException("Error while storing KeyPair");
		}
	}

	/**
	 * Delete cloud configuration key
	 * @param cloudServiceProvider
	 * @param key
	 * @return
	 */
	@ApiOperation(value = "delete cloud configuration keys by cloud service provider and key", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request")})
	@LogRequest
	@DeleteMapping("/vUser/deletespkey/{cloudserviceprovider}/{key}")
	@AclCheck(value = "*:iam:d,*:cloud service configuration:d",page=MODULE_NAME)
	public ResponseEntity<?> deleteSpkey(@ApiParam(name="cloudServiceProvider",value = "cloud service provider") @PathVariable("cloudserviceprovider") String cloudServiceProvider,
			@ApiParam(name="key",value = "key") @PathVariable("key") String key) { // use UserMgmtdto
		Long userId = SecurityContextUtil.getLoginUserRecordId();
		if (key == null || cloudServiceProvider == null) {
			log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			throw new ConstraintViolationException("User Id is null", null);
		}
		log.debug("UserController::adding/updating spkey for user {} and key {}", userId, key);
		FusionMessage msg = fusionUserAccountService.deleteServiceProviderKey(userId, key, cloudServiceProvider);
		if (msg == null) {
			log.error("Cannot delete the user key.");
			msg = new FusionMessage(null, MessageUtil.getMessage("delete.unsuccessful.msg"), true);
		}
		return new ResponseEntity<>(msg, HttpStatus.OK);
	}

    /**
     * This method gets the user information for the supplied id.
     * 
     * @param userid
     * @return
     */
	@ApiOperation(value = "returns user information for the supplied user id", response = VUserdto.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 401, message = "Unauthorized")})
    @LogRequest
    @GetMapping("/vUsers/getone/{id}")
	@AclCheck(value = "*:user management:r",page=MODULE_NAME)
    public ResponseEntity<?> getUserDetails(@ApiParam(name="userid",value = "supplied user id") @PathVariable("id") Long userid) {
    	if (userid == null) {
    		log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
    		throw new ConstraintViolationException("User Id is null", null);
    	}
    	String loggedInUserName = SecurityContextUtil.getLoginUserName();
    	VUserdto userdto = fusionUserAccountService.getUserDetails(loggedInUserName, userid);
    	UUID userdtoTenantId = userdto.getTenantId();
    	if (userdto != null && TenantUtil.canAccessTeantData(userdtoTenantId))
    		return new ResponseEntity<>(userdto, HttpStatus.OK);
    	else {
    		log.error(MessageKeyConstants.UNAUTHORIZED_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
            return new ResponseEntity<>(MessageUtil.getMessage("view.notauthorized.0016"),HttpStatus.UNAUTHORIZED);
    	}    
    }

    /**
     * API to return All User details
     * @return
     */
	@ApiOperation(value = "returns all user details", response = Iterable.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 404, message = "Not Found"),
							@ApiResponse(code = 401, message = "Unauthorized")})
    @LogRequest
    @GetMapping("/vUsers/list")
	@AclCheck(value = "*:user management:r",page=MODULE_NAME)
    public ResponseEntity<?> getAllUserDetails(@ApiParam(name="tenantId",value = "tenant id")  @RequestParam("tenantId") String tenantId) throws Exception{
    	if (StringUtils.isBlank(tenantId)) {
    		log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
    		throw new ConstraintViolationException("TenatId is required.", null);
    	}
    	UUID targetDataTenantId = UUID.fromString(tenantId);
        if (TenantUtil.canAccessTeantData(targetDataTenantId) ) {
        	List<VUserdto> userlist;
			if (TenantUtil.canAccessUsersData(tenantId)) {
				userlist = fusionUserAccountService.getAllUserDetails(TenantUtil.getTenantId(tenantId), FusionConstants.TENANTTYPE_CSP);
			} else {
				userlist = fusionUserAccountService.getAllUserDetails(TenantUtil.getTenantId(tenantId), FusionConstants.TENANTTYPE_CUSTOMER);
			}
        	if (userlist != null)
        		return new ResponseEntity<>(userlist, HttpStatus.OK);
        	else 
        		return new ResponseEntity<>(new FusionMessage("0008", MessageUtil.getMessage("nouser.found.0008"), true), HttpStatus.NOT_FOUND);
        } 
        else {
            log.error(MessageKeyConstants.UNAUTHORIZED_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
        	return new ResponseEntity<>(new FusionMessage("0016", MessageUtil.getMessage("view.notauthorized.0016"), true),
    				HttpStatus.UNAUTHORIZED);
        }
    }
    
    /**
     * Create new user with permission.
     * @param userdto
     * @return
     */
	@ApiOperation(value = "create new user with permission", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 201, message = "Created"),
							@ApiResponse(code = 400, message = "Bad Request"),
							@ApiResponse(code = 401, message = "Unauthorized"),
							@ApiResponse(code = 500, message = "Internal Server Error")})
	@LogRequest
	@PostMapping("/vUsers/create")
	@AclCheck(value = "*:user management:w",page=MODULE_NAME)
	public ResponseEntity<?> createUser(@ApiParam(name="body",value = "creates new user with permission") @RequestBody VUserdto userdto) { // use UserMgmtdto
		ResponseEntity<?> ret = null;
		if (userdto == null) {
			log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			throw new ConstraintViolationException("Error creating user", null);
		}
		if (TenantUtil.canAccessTeantData(userdto.getTenantId())) {
			try {
				log.debug("Started Creating User for {} .... ",userdto.getEmail());
				userdto.setUsername(userdto.getEmail());
				List<VUser> users = vuserJpaRepo.findByEmailIgnoreCaseAndIsactiveTrue(userdto.getEmail());
				
				if (!users.isEmpty()) {
					FusionMessage msg = new FusionMessage("0015", MessageUtil.getMessage("email.alreadyexists.0015"),true);
					return new ResponseEntity<>(msg, HttpStatus.BAD_REQUEST);
				}
				
				UUID tenantid = userdto.getTenantId() == null ? SecurityContextUtil.getLoginUserTenantId()
						: userdto.getTenantId();
				VUser createUser = DtoEntityMapper.getVUsertocreate(userdto, tenantid, daysRegTokenValid);

				String loggedInUserName = SecurityContextHolder.getContext().getAuthentication().getName();
				VUser createdUser = fusionUserAccountService.create(loggedInUserName, createUser);

				if (createdUser == null) {
					String msg = ", Error in creating user";
					log.error(msg);
					throw new FusionException(null, "create.unsuccessful.msg", msg);
				}
				fusionUserAccountService.createPermission(createdUser, userdto.getUsertofeaturepermission());

				// send token link Email to User
				fusionUserAccountService.emailUserRegistrationLink(createdUser);
				
				FusionMessage msg = new FusionMessage(null, MessageUtil.getMessage("create.successful.msg"), false);
				msg.setInfo(createdUser.getId().toString());
				ret = new ResponseEntity<>(msg, HttpStatus.CREATED);
				
			} catch (Exception e) {
				log.error("Error in creating user: " + e.getMessage() + "\n" + e.getCause() );
				ret = new ResponseEntity<>(
						new FusionMessage(null, MessageUtil.getMessage("create.unsuccessful.msg"), true),
						HttpStatus.INTERNAL_SERVER_ERROR);
			}
			return ret;
		}
		log.error(MessageKeyConstants.UNAUTHORIZED_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
		return new ResponseEntity<>(new FusionMessage("0003", MessageUtil.getMessage(MessageKeyConstants.UNAUTHORIZED_003), true),
				HttpStatus.UNAUTHORIZED);

	}

	/**
	 * Update user detail and permission
	 * @param aVUserdto
	 * @return
	 * @throws Exception
	 */
	@ApiOperation(value = "updates user detail and permission", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request"),
							@ApiResponse(code = 401, message = "Unauthorized")})
	@LogRequest
	@PutMapping(value = "/vUsers/update")
	@AclCheck(value = "*:user management:w",page=MODULE_NAME)
	public ResponseEntity<?> updateUser(@ApiParam(name="body",value = "updates user detail and permission") @RequestBody VUserdto aVUserdto) throws Exception {
		if (aVUserdto == null) {
			log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			throw new ConstraintViolationException(ERROR_MSG, null);
		}
		VUser vuser = vuserJpaRepo.getOne(aVUserdto.getId());
		if(vuser==null) {
			log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			return new ResponseEntity<>(new FusionMessage("0030",
					MessageUtil.getMessage("record.notexist.msg.0030"), true), HttpStatus.BAD_REQUEST);
		}
		//Permission check
		if (! TenantUtil.canAccessTeantData(vuser.getTenantid())) {
			log.error(MessageKeyConstants.UNAUTHORIZED_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId()  );
			return new ResponseEntity<>(MessageUtil.getMessage(MessageKeyConstants.UNAUTHORIZED_003),HttpStatus.UNAUTHORIZED);
		}		
		vuser = DtoEntityMapper.updateVuserFromDto(aVUserdto,vuser);
		String loggedInUserName = SecurityContextHolder.getContext().getAuthentication().getName();
		Map<String, Object> updatedUser = fusionUserAccountService.update(loggedInUserName,vuser);
		fusionUserAccountService.updatePermission(vuser,aVUserdto.getUsertofeaturepermission()); //update user permission
		VUser v = (VUser) updatedUser.get(VUSER);
		if(v==null)
			new ResponseEntity<>(updatedUser.get(ERROR), HttpStatus.OK);
		return new ResponseEntity<>(new FusionMessage(null, MessageUtil.getMessage("update.successful.msg"), false), HttpStatus.OK);
	}
	
	/**
	 * To delete a user. This would be only soft deletion.
	 * 
	 * @param id
	 * @return
	 */
	@ApiOperation(value = "deletes a user. This would be only soft deletion", response = String.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request"),
							@ApiResponse(code = 401, message = "Unauthorized")})
	@LogRequest
	@DeleteMapping(value = "/vUsers/delete/{id}")
	@AclCheck(value = "*:user management:d",page=MODULE_NAME)
	public ResponseEntity<?> delete(@ApiParam(name="id",value = "user id") @PathVariable Long id) {
		if (id == null) {
			log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			throw new ConstraintViolationException("Error deleting user", null);
		}
		Optional<VUser> userToDelete = vuserJpaRepo.findById(id);
		if(userToDelete.isEmpty()) {
			log.error(MessageKeyConstants.BAD_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			return new ResponseEntity<> (MessageUtil.getMessage("usercontroller.deleteuser.error.msg.0120"), HttpStatus.BAD_REQUEST);
		}
		ResponseEntity<?> ret = null;
		if (TenantUtil.canAccessTeantData(userToDelete.get().getTenantid())) {
			String loggedInUserName = SecurityContextUtil.getLoginUserName();
			boolean bool = fusionUserAccountService.delete(loggedInUserName, id);
			if (bool)
				ret = new ResponseEntity<>(MessageUtil.getMessage("usercontroller.deleteuser.success.msg"), HttpStatus.OK);
			else
				ret = new ResponseEntity<>(MessageUtil.getMessage("usercontroller.deleteuser.error.msg.0120"),HttpStatus.OK);
		}
		else {
			log.error(MessageKeyConstants.UNAUTHORIZED_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			ret = new ResponseEntity<>(MessageUtil.getMessage(MessageKeyConstants.UNAUTHORIZED_003),HttpStatus.UNAUTHORIZED);
		}
		return ret;
	}
    
    /**
     * Get user's KeyPair
     * 
     * @return KeyPair
     */
	@ApiOperation(value = "returns user's key pair", response = UserXsKeyPairResponseDto.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK")})
    @LogRequest
    @GetMapping("/getxskeypair")
	@AclCheck(value = "*:iam:r,*:cloud service configuration:r",page=MODULE_NAME)
    public ResponseEntity<UserXsKeyPairResponseDto> getUserXStreamKeyPair() {
        String username = SecurityContextUtil.getLoginUserName();
        UUID tenantid = SecurityContextUtil.getLoginUserTenantId();
        String name=null;
        UserXsKeyPairResponseDto dto = fusionUserAccountService.getUserXsKeyPair(tenantid, username, name);
        if (dto == null) {
            return ResponseEntity.notFound().build();
        } else {
            return ResponseEntity.ok(dto);
        }
    }
    
    /**
     * Note that this api is public.
     * @param aToken
     * @return
     * @throws Exception
     */
	@ApiOperation(value = "validates registration token", response = UserRegistrationTokenValidationDto.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request"),
							@ApiResponse(code = 401, message = "Unauthorized")})
    @GetMapping("/register")
    public ResponseEntity<?> validateRegistrationToken(@ApiParam(name="aToken",value = "registration token") @RequestParam("token") String aToken) throws Exception {
    	if (StringUtils.isBlank(aToken)) {
    		log.warn("A user is trying to register without a registration token.");
    		UserRegistrationTokenValidationDto dto = new UserRegistrationTokenValidationDto();
    		return new ResponseEntity<>(dto, HttpStatus.BAD_REQUEST); 
    	}
    	UserRegistrationTokenValidationDto dto = this.fusionUserAccountService.validateUserRegistrationToken(aToken);
    	if (!dto.isValid()) {
    		log.error("Failed to register a new user: userid[{}]", dto.getId());
    		return new ResponseEntity<>(dto, HttpStatus.BAD_REQUEST);
    	}
    	else { 
    		log.info("A user registration is successful: userid[{}]", dto.getId());
			return new ResponseEntity<>(dto, HttpStatus.OK);
    	}
    }
    
    /**
     * To save new user's registration info. Not that is a public API
     * @param userdto
     * @return
     */
	@ApiOperation(value = "saves new user's registration info", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request"),
							@ApiResponse(code = 401, message = "Unauthorized")})
    @PutMapping("/updateUserInfo")
    public ResponseEntity<?> saveNewUserRegistration(@ApiParam(name="body",value = " saves new user's registration info ") @RequestBody VUserdto userdto) throws Exception {
		if (userdto == null || userdto.getId() == null) {
			log.warn("Bad request in user registration.");
			throw new ConstraintViolationException(ERROR_MSG, null);
		}
		if (this.enforceMfa && !StringUtils.isNumeric(userdto.getGooglePin())) {
			log.error("User inputs non numeric PIN number. userid[{}]", userdto.getId());
			throw new BadCredentialsException("Invalid Google Authenticator PIN code.");
		}
		// check password validity
		if (!PasswordPolicyValidator.isPasswordValid(userdto.getPassword())) {
			log.error("User inputs an invalid password. userid[{}]", userdto.getId());
			return new ResponseEntity<>(new FusionMessage(null, MessageUtil.getMessage("usercontroller.registration.password.policy.msg"), true), HttpStatus.BAD_REQUEST);
		}
		VUser vuser = vuserJpaRepo.getOne(userdto.getId());
		if(vuser==null) {
			log.warn("User ID is invalid. userid[{}]", userdto.getId());
			return new ResponseEntity<>(new FusionMessage("0030",
					MessageUtil.getMessage("record.notexist.msg.0030"), true), HttpStatus.FORBIDDEN);
		}
			// to validate the Google Pin
		if (this.enforceMfa) {
			if ( StringUtils.isBlank(vuser.getMfaCode()) ){
				log.error("User's MFA code in DB is empty. userid[{}]", userdto.getId());
				throw new Exception(ERROR_MSG);
			}
			final Totp totp = new Totp(vuser.getMfaCode());
			if (!totp.verify(userdto.getGooglePin())) {
				log.error("User inputs invalid PIN number. userid[{}]", userdto.getId());
				throw new BadCredentialsException("Invalid Google Authenticator PIN code.");
			}
			else
				userdto.setMfaEenable(true);   //mfa is enabled
		}
		// hashing the password
		String hashingString = passwordEncoder.encode(userdto.getPassword());
		userdto.setPassword(hashingString);
		VUserdto saveUserdto = fusionUserAccountService.saveUserRegistrationInfo(userdto);
		if (saveUserdto == null || saveUserdto.getId() == null) {
			log.error("Failed to register user: userid[{}]", userdto.getId());
			return new ResponseEntity<>("Bad Request!", HttpStatus.BAD_REQUEST);
		}
		log.info("User registration is successful for userid[{}]", userdto.getId());
		return new ResponseEntity<>(new FusionMessage(null, MessageUtil.getMessage("update.successful.msg"), false), HttpStatus.OK);
    }
    
    
    
    /**
     * To extend user registration token expiration date another 7 days. 
     * @param userId
     * @return
     * @throws Exception
     */
	@ApiOperation(value = "extends user registration token expiration date", response = Iterable.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request")})
    @AclCheck(value = "*:user management:*",page=MODULE_NAME)
	@GetMapping("/vUser/extendRegistrationTokenExpirationDate")
    public ResponseEntity<?> extendRegistrationTokenDate(@ApiParam(name="userId",value = "user id") @RequestParam("id") String userId) throws Exception {
    	if (StringUtils.isBlank(userId) || !StringUtils.isNumeric(userId) ) {
    		log.warn("Invaid user id in the request.");
    		UserRegistrationTokenValidationDto dto = new UserRegistrationTokenValidationDto();
    		dto.setMessage("Invalid User ID");
    		return new ResponseEntity<>(dto, HttpStatus.BAD_REQUEST); 
    	}
    	
    	Date exendedDate = fusionUserAccountService.extendRegistrationTokenDate( Long.valueOf(userId), this.daysRegTokenValid );
    	if (exendedDate == null) {
    		log.error("Failed to extend user registration token expiration date: userid[{}]", userId);
    		return new ResponseEntity<>("Failed to extend user's registration token expiration date.", HttpStatus.BAD_REQUEST);
    	}
    	else { 
    		log.info("A user registration token expiration date is extended successfully: userid[{}]", userId);
			return new ResponseEntity<>("User registration token expiration date is extended.", HttpStatus.OK);
    	}
    }
    
    /**
     * To resend user registration token email 
     * @param userId
     * @return
     * @throws Exception
     */
	@ApiOperation(value = "extends user registration token expiration date", response = String.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request"),
							@ApiResponse(code = 401, message = "Unauthorized")})
    @AclCheck(value = "*:user management:*",page=MODULE_NAME)
    @GetMapping("/vUsers/resendUserRegistrationEmail")
    public ResponseEntity<?> resendUserRegistrationEmail(@ApiParam(name="userId",value = "user id") @RequestParam("id") String userId) throws Exception {
    	if (StringUtils.isBlank(userId) || !StringUtils.isNumeric(userId) ) {
    		log.warn("Invaid user id in the request.");
    		UserRegistrationTokenValidationDto dto = new UserRegistrationTokenValidationDto();
    		dto.setMessage("Invalid User ID");
    		return new ResponseEntity<>(dto, HttpStatus.BAD_REQUEST); 
    	}
    	boolean sendStatus = fusionUserAccountService.resendRegistrationTokenEmail(Long.valueOf(userId), this.daysRegTokenValid);    	    	
    	if (!sendStatus) {
    		log.error("Resending the user registration email failed.  userid: {}", userId);
    		return new ResponseEntity<>("Resending the user registration email failed.", HttpStatus.BAD_REQUEST);
    	}
    	else { 
    		log.info("Resending the user registration email is successful: userid: {}", userId);
			return new ResponseEntity<>("Resending the user registration email is successful.", HttpStatus.OK);
    	}
    }
    
	/**
	 * Retrieve RIDs from TrustPlatform db that belongs to the logged in user. This
	 * endpoint is used solely in SIOC to filter data showed in Results Alert Report
	 * and should be called for user associated to a customer tenant and not CSP.
	 * 
	 * For logged in user whose tenant type is CSP, RID will be pulled from tenant
	 * record of the selected customer tenant UUID.
	 * 
	 * @param customerTenantid UUID of the selected customer. This is mandatory when
	 *                         tenant type of the logged in user is CSP.
	 * @return GetUserridsResponseDto
	 */
	@ApiOperation(value = "retrieve RIDs", response = GetUserridsResponseDto.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK")})
	@AclCheck(value = "*:alert dashboard:r",page=MODULE_NAME)
	@GetMapping("/userrids")
	public GetUserridsResponseDto listUserRIDs(
			@ApiParam(name="customerTenantid",value = "customer tenant id") @RequestParam(required = false, name = "tenantId") String customerTenantid) {
		UUID tenantid;
		var isFetchHfwFlagOnly = false;
		boolean isCsp = SecurityContextUtil.isCsp();
		if (isCsp && StringUtils.isBlank(customerTenantid)) {
			log.error("Param tenantId (customer UUID) is required when user is a CSP");
			throw new ConstraintViolationException("tenantId is blank", null);
		} else if (isCsp) {
			tenantid = UUID.fromString(customerTenantid);
			// If supplied tenant is CSP tenant, no need to pull RIDs. Need to only fetch hfw flag.
			isFetchHfwFlagOnly = tenantid.equals(SecurityContextUtil.getLoginUserTenantId());
		} else {
			tenantid = SecurityContextUtil.getLoginUserTenantId();
		}
		Tenant tenant = tenantService.findOne(tenantid);
		if (tenant == null) {
			log.error("Unable to find an active record for tenant {}.", tenantid);
			throw new ConstraintViolationException("Tenant not found", null);
		}
		GetUserridsResponseDto respDto = new GetUserridsResponseDto();
		respDto.setFetchhostfwlogs(tenant.isFetchhostfwlogs());
		List<String> rids;
		if (isCsp) {
			// When selected tenant is CSP tenant, default rids to * (all). Otherwise, grab all RIDs
			// configured for the supplied customer tenant.
			rids = isFetchHfwFlagOnly ? List.of("*")
					: Stream.of(tenantService.findRIDs(tenantid, CSPType.XSTREAM),
							tenantService.findRIDs(tenantid, CSPType.GCP),
							tenantService.findRIDs(tenantid, CSPType.AZURE),
							tenantService.findRIDs(tenantid, CSPType.APEX)).flatMap(List::stream).map(rid -> rid)
							.distinct().collect(toList());
		} else {
			// 03/25/2021: Include the RIDs for GCP from the logged in user's tenant record
			// (gcp_info JSON field).
			// 04/26/2021: Include the RIDs for Azure from the logged in user's tenant
			// record.
			rids = fusionUserAccountService.findUserRids(tenantid, SecurityContextUtil.getLoginUserRecordId());
		}
		log.info("rids: {}", rids);
		respDto.setRids(rids);
		return respDto;
	}
    
    /**
     * TRPL-110 : To send email if user forgot password
     * @param email
     * @return
     * @throws Exception
     */
	@ApiOperation(value = "sends email if user forgot password", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 404, message = "Not Found")})
	@GetMapping("/forgotpasswordrequest")
    public ResponseEntity<?> forgotpassword(@ApiParam(name="email",value = "email") @RequestParam("email") String email){
    	ResponseEntity<FusionMessage> resp = null;
    	if (StringUtils.isBlank(email) ) {
    		log.warn("A user is not sending email.");
			throw new ConstraintViolationException("Error processing forgot password request", null);
    	}
    	FusionMessage fm = fusionUserAccountService.forgotPassword(email,daysRegTokenValid);
		if (fm == null) {
			resp = new ResponseEntity<>(new FusionMessage(null,
					MessageUtil.getMessage("notificationservice.forgotPasswordRequest.success.msg"), false),
					HttpStatus.OK);
		} else {
			resp = new ResponseEntity<>(fm, HttpStatus.NOT_FOUND);
		}
		return resp;
    }
    
    /**
     * TRPL-110 Validate forgotpassword token
     * @param aToken
     * @return
     * @throws Exception
     */
	@ApiOperation(value = "validates forgot password token", response = ForgotPasswordTokenValidationDto.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request")})
	@GetMapping("/forgotpassword")
    public ResponseEntity<?> validateForgotPasswordToken(@ApiParam(name="aToken",value = "forgotpassword token") @RequestParam("token") String aToken) throws Exception {
    	if (StringUtils.isBlank(aToken)) {
    		log.warn("A user is not sending forgotpassword token.");
    		return new ResponseEntity<>("Invalid Registration Token!", HttpStatus.BAD_REQUEST); 
    	}
    	ForgotPasswordTokenValidationDto dto = this.fusionUserAccountService.validateForgotPasswordToken(aToken);
    	if (!dto.isValid()) {
    		log.error("Failed to validate forgotpassword token for : userid[{}]",dto.getId());
    		return new ResponseEntity<>(dto, HttpStatus.BAD_REQUEST);
    	}
    	else { 
    		log.info("A forgotpasword token validation is successful: userid[{}]", dto.getId());
			return new ResponseEntity<>(dto, HttpStatus.OK);
    	}
    }
    
    /**
     * TRPL-110 reset password for user after token validation
     * @param dto
     * @return
     */
	@ApiOperation(value = "resets password for user after token validation", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request")})
    @PostMapping("/resetpasswordrequest")
	public ResponseEntity<?> resetUserPasswordRequest(@ApiParam(name="body",value = " resets password") 	@RequestBody PasswordResetDto dto) {
    	if (dto == null || dto.getUserId() == null ||  StringUtils.isAnyBlank(dto.getEmail(),dto.getNewpwd())) {
			throw new ConstraintViolationException("Request Payload Error", null);
		}
    	return changePassword(dto);
    }
    
    /**
     * TRPL-110 Change the password for user
     * @param dto
     * @return
     */
	@ApiOperation(value = "changes the password for user", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 401, message = "Unauthorized"),
							@ApiResponse(code = 400, message = "Bad Request.")})
    @LogRequest
    @PutMapping(value = "/vUser/changepassword")
    public ResponseEntity<?> resetUserPassword(@ApiParam(name="body",value = "changes the password") @RequestBody PasswordResetDto dto) {
    	if (dto == null || dto.getUserId() == null ||StringUtils.isAnyBlank(dto.getOldpwd(),dto.getNewpwd(), dto.getEmail())) {
			log.error(MessageKeyConstants.UNAUTHORIZED_REQUEST_MSG, SecurityContextUtil.getLoginUserName());
			throw new ConstraintViolationException("Request Payload Error", null);
		}
    	VUser vuser = vuserJpaRepo.getOne(dto.getUserId());
    	
    	if (!TenantUtil.canAccessTeantData(vuser.getTenantid())) {
			log.error(MessageKeyConstants.UNAUTHORIZED_REQUEST_MSG, SecurityContextUtil.getLoginUserRecordId());
			return new ResponseEntity<>(MessageUtil.getMessage(MessageKeyConstants.UNAUTHORIZED_003),HttpStatus.UNAUTHORIZED);
		}
    	
    	Usercredential ucr= vuser.getUsercredentialsCollection().stream().findFirst().orElse(null);
    	
    	if(dto.getOldpwd().equals(dto.getNewpwd())) {
    		log.warn("Current password and new password should not same for user {} ",dto.getEmail());
			return new ResponseEntity<>(new FusionMessage(null, 
				MessageUtil.getMessage("notificationservice.resetPassword.pwdsame.msg"), true), HttpStatus.BAD_REQUEST);
    	}
    	else if(ucr!=null && (passwordEncoder.matches(dto.getOldpwd(),ucr.getPassword()))) {
    		log.debug("Current password matched.");
    		return changePassword(dto);
    	}else {
    			log.error("Current password not matched for user {} ",dto.getEmail());
    			return new ResponseEntity<>(new FusionMessage(null, 
    				MessageUtil.getMessage("notificationservice.resetPassword.invalidpwd.msg"), true), HttpStatus.BAD_REQUEST);
    		}
    }
    
    private ResponseEntity<?> changePassword(PasswordResetDto dto) {
    	if (!PasswordPolicyValidator.isPasswordValid(dto.getNewpwd())) {
			log.error("User inputs an invalid password. userid[{}]", dto.getUserId());
			return new ResponseEntity<>(new FusionMessage(null, MessageUtil.getMessage("usercontroller.registration.password.policy.msg"), true), HttpStatus.BAD_REQUEST);
		}
    	 String hashing =  passwordEncoder.encode(dto.getNewpwd());
    	FusionMessage fm = fusionUserAccountService.resetPassword(dto.getUserId(), dto.getEmail(), hashing);
    	return new ResponseEntity<>(fm, HttpStatus.OK);
    }
    
	/**
	 * This method to check whether refresh_token exists for the logged in user or
	 * not.
	 * 
	 * @return
	 * @throws Exception 
	 */
    @ApiOperation(value = " checks whether refresh_token exists for the logged in user or not", response = Map.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK"),
							@ApiResponse(code = 400, message = "Bad Request.")})
	@GetMapping("/checkrefreshtoken")
	@AclCheck(value = "*:cloud service configuration:*",page=MODULE_NAME)
	public ResponseEntity<?> checkRefreshToken(@ApiParam(name="cloud",value = "type of the cloud") @RequestParam("cloud") String cloud,
			@ApiParam(name="selectedTenantId",value = "selected tenant id") @RequestParam("tenantId") String selectedTenantId) throws Exception {
		if (StringUtils.isBlank(cloud)) {
			log.warn("User is not sending Cloud.");
			return new ResponseEntity<>("Invalid cloud!", HttpStatus.BAD_REQUEST);
		}
		Long userId = SecurityContextUtil.getLoginUserRecordId();
		UUID tenantId = SecurityContextUtil.getLoginUserTenantId();

		Map<String, Boolean> cloudTokenMap = fusionUserAccountService.checkRefreshToken(userId, tenantId,
				UUID.fromString(selectedTenantId), cloud);
		return new ResponseEntity<>(cloudTokenMap, HttpStatus.OK);
	}
	@ApiOperation(value = " process authorization code", response = FusionMessage.class)
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK")})
	@LogRequest
	@LogExecutionTime
	@PostMapping("/processAuthCode")
	@AclCheck(value = "*:cloud service configuration:*",page=MODULE_NAME)
	public ResponseEntity<?> processAuthCode(@ApiParam(name="body",value = "process authorization code") @RequestBody @Valid AuthCodeDto authCodeDto,@ApiParam(name="cloud",value = "type of the cloud") @RequestParam String cloud)
			throws Exception {
		Long userId = SecurityContextUtil.getLoginUserRecordId();
		UUID loggedInTenantId = SecurityContextUtil.getLoginUserTenantId();
		FusionMessage message = fusionUserAccountService.processAuthCode(authCodeDto, loggedInTenantId, cloud, userId);
		return new ResponseEntity<>(message, HttpStatus.OK);
	}
	@ApiOperation(value = " removes ping token")
	@ApiResponses(value = { @ApiResponse(code = 200, message = "OK")})
	@GetMapping("/removepingtoken")
	public void revokePingAuthToken() {
		pfIntegrateService.revokePingToken();
	}
}
