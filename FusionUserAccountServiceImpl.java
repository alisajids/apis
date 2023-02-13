/*
 * Copyright (c) 2019-2022 Virtustream Corporation 
 * All Rights Reserved
 *
 * This software contains the intellectual property of Virtustream Corporation
 * or is licensed to Virtustream Corporation from third parties. Use of this
 * software and the intellectual property contained therein is expressly
 * limited to the terms and conditions of the License Agreement under which
 * it is provided by or on behalf of Virtustream.
 *
 */
package com.virtustream.trustplatform.services.impl;

import static com.virtustream.common.util.constant.FusionConstants.ERROR;
import static com.virtustream.common.util.constant.FusionConstants.MAIL_TEMPLATE;
import static com.virtustream.common.util.constant.FusionConstants.VUSER;
import static com.virtustream.common.util.constant.FusionConstants.XSTREAMONE;
import static java.util.stream.Collectors.toList;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.validation.ConstraintViolationException;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.jboss.aerogear.security.otp.api.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.reflect.TypeToken;
import com.microsoft.aad.msal4j.MsalInteractionRequiredException;
import com.virtustream.common.db.model.Tenant;
import com.virtustream.common.db.model.Tpfeature;
import com.virtustream.common.db.model.Tppermission;
import com.virtustream.common.db.model.UserNotification;
import com.virtustream.common.db.model.Usercredential;
import com.virtustream.common.db.model.Usertofeaturepermission;
import com.virtustream.common.db.model.VUser;
import com.virtustream.common.db.repository.TenantJpaRepository;
import com.virtustream.common.db.repository.TpfeatureJpaRepository;
import com.virtustream.common.db.repository.TppermissionJpaRepository;
import com.virtustream.common.db.repository.UserNotificationRepository;
import com.virtustream.common.db.repository.UsercredentialJpaRepository;
import com.virtustream.common.db.repository.UsertofeaturepermissionJpaRepository;
import com.virtustream.common.db.repository.VUserJpaRepository;
import com.virtustream.common.dto.AuthCodeDto;
import com.virtustream.common.dto.CspInfoDto;
import com.virtustream.common.dto.ForgotPasswordTokenValidationDto;
import com.virtustream.common.dto.FusionMessage;
import com.virtustream.common.dto.MailDTO;
import com.virtustream.common.dto.NameValuePair;
import com.virtustream.common.dto.RefreshTokendto;
import com.virtustream.common.dto.ServiceproviderKeyInfoResponseDto;
import com.virtustream.common.dto.UserRegistrationTokenValidationDto;
import com.virtustream.common.dto.UserXsKeyPairResponseDto;
import com.virtustream.common.dto.VUserdto;
import com.virtustream.common.dto.gcp.GCPTokenDto;
import com.virtustream.common.enums.CSPType;
import com.virtustream.common.exception.AccountServiceException;
import com.virtustream.common.exception.FusionException;
import com.virtustream.common.exception.GCPAuthenticationException;
import com.virtustream.common.services.FusionEncryptionService;
import com.virtustream.common.services.MailService;
import com.virtustream.common.services.UserRIDService;
import com.virtustream.common.services.client.CSPClientFactory;
import com.virtustream.common.services.client.CloudServiceProviderClient;
import com.virtustream.common.services.client.gcp.GCPOAuthAPI;
import com.virtustream.common.util.DtoEntityMapper;
import com.virtustream.common.util.FusionCalendarUtil;
import com.virtustream.common.util.FusionStringUtil;
import com.virtustream.common.util.GsonUtil;
import com.virtustream.common.util.JsonUtil;
import com.virtustream.common.util.MessageUtil;
import com.virtustream.common.util.RandomKeyGenerator;
import com.virtustream.common.util.constant.FusionConstants;
import com.virtustream.trustplatform.aop.LogRequest;
import com.virtustream.trustplatform.services.AzureService;
import com.virtustream.trustplatform.services.FusionUserAccountService;
import com.virtustream.trustplatform.services.GCPService;
import com.virtustream.trustplatform.services.TenantService;

import lombok.extern.slf4j.Slf4j;

/**
 * This class provides user account level services.
 * 
 * @author
 *
 */
@Slf4j
@Service
public class FusionUserAccountServiceImpl implements FusionUserAccountService {

	public static final String QR_PREFIX = "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=";
	public static final String APP_NAME = "TrustPlatform";

	static final Logger logger = LoggerFactory.getLogger(FusionUserAccountServiceImpl.class);
	
	public static final String TITLE_USERACCOUNTS = "UserAccounts";
	private static final String DAE = "Data Access Exception";
	private static final String ERROR_MSG="Error msg: ";

	@Value("${ui-server-url}")
	private String uiServerURL;

	@Autowired
	private VUserJpaRepository vuserJpaRepo;
	
	@Autowired
	private UsertofeaturepermissionJpaRepository usertofeaturepermissionJpaRepo;
	
	@Autowired 
	private TpfeatureJpaRepository tpfeatureJpaRepo;
	
	@Autowired
	private TppermissionJpaRepository tppermissionJpaRepo;
	
	@Autowired
	private  MailService mailService;

	@Autowired
	private UsercredentialJpaRepository ucJpaRepo;

	@Autowired
	private TenantJpaRepository tenantJpaRepo;

	@Autowired
	private TenantService tenantService;

	@Autowired
	private FusionEncryptionService encryptionService;

	@Autowired
    private UserRIDService userridService;
	
	@Autowired
	private AzureService azureService;
	
	@Autowired
	private GCPService gcpService;
	
	@Autowired
	private GCPOAuthAPI gcpAuthApi;

	@Autowired
	private CSPClientFactory cspclientfactory;
	
	@Autowired
	private UserNotificationRepository userNotificationRepository;
	
	private static final String ACCESS_TOKEN_EXISTS="accessTokenExists";
	private static final String DELETE_SUCCESSFUL_MSG="delete.successful.msg";
	

	public VUser findVUser(String userName) {

		if (userName == null) {
			log.error("User Name is missing");
			throw new AccountServiceException("User Name is missing");
		}

		List<VUser> users = null;
		VUser user = null;
		try {
			users = vuserJpaRepo.findByUsernameIgnoreCaseAndIsactiveTrueAndStatusTrue(userName);
			if (users == null || users.isEmpty()) {
				log.warn("User not found: " + userName);
			} else {
				user = users.get(0);
			}
		} catch (DataAccessException dae) {
			log.error(DAE + ": " + dae.getMessage() + "\n " + dae.getCause());
			throw new AccountServiceException(DAE, dae);
		}
		return user;
	}
	
	@Transactional
	@Override
	public boolean recordUserLoginFailures(String userName, String fromIPaddress) {
		log.debug("Entering FusionUserAccountServerImpl::recordUserLoginFailures");
		boolean flag = false;
		try {
			VUser currentUser = findVUser(userName);
			if (currentUser == null)
				return flag;
			flag = true;
			int failCount = (currentUser.getLoginfailurecount() == null) ? 1 : currentUser.getLoginfailurecount() + 1;
			currentUser.setLoginfailurecount(failCount);
			currentUser.setLoginfailureip(fromIPaddress);
			currentUser.setLastloginfailuretime(new Timestamp(new Date().getTime()));
			vuserJpaRepo.saveAndFlush(currentUser);
		} catch (DataAccessException dae) {
			log.error(DAE + ": " + dae.getMessage() + "\n" + dae.getCause());
			throw new AccountServiceException(DAE, dae);
		}
		log.debug("Exiting FusionUserAccountServerImpl::recordUserLoginFailures");
		return flag;
	}

	/**
	 * This method resets the user login failure count to 0
	 * 
	 * @param userName
	 */
	@Transactional
	@Override
	public void cleanUserLoginFailureCount(String userName) {
		VUser currentUser = findVUser(userName);
		currentUser.setLoginfailurecount(0);
		vuserJpaRepo.saveAndFlush(currentUser);
	}

	/**
	 *
	 * @param userName
	 * @param createPassword
	 */
	@Override
	@Transactional (rollbackFor=Exception.class)
	public void createPassword(String userName, String createPassword) {
		log.debug("Entering FusionUserAccountServerImpl::createPassword");
		try {
			if ((userName == null) || (createPassword == null)) {
				log.error("Missing user name or changed passsword ");
				throw new AccountServiceException("Missing user id or create passsword");
			}

			List<VUser> users = vuserJpaRepo.findByUsernameIgnoreCaseAndIsactiveTrueAndStatusTrue(userName);
			VUser user = users.get(0);
			Long userId = user.getId();
			log.debug("create pass for User Id {}",userId);
			Usercredential uc = ucJpaRepo.findByUserId(userId);
			if (uc != null) {
				log.error("User credential Information exists, cannot create password: " + userId);
				throw new AccountServiceException(
						"User credential Information exists, cannot create password: " + userId);
			}

			// Since the password is being created, a new Usercredential is
			uc = new Usercredential();
				uc.setPassword(createPassword);
				uc.setActivateddate(new Date());
				uc.setIsactive(true);
				uc.setTenantid(user.getTenantid());
				uc.setUserId(userId);
				Usercredential createdUc = ucJpaRepo.save(uc);
				log.debug("UC created id {}",createdUc.getId());
		}	
		catch (DataAccessException dae) {
			log.error(DAE + ": " + dae.getMessage() + " " + dae.getCause());
			throw new AccountServiceException(DAE, dae);
		}
		log.debug("Exiting FusionUserAccountServerImpl::createPassword");
	}


	/**
	 * This method returns user details given a user's id
	 * 
	 * @param id
	 */
	public VUser findVUser(Long id) {

		if (id == null) {
			log.error("User Id is missing");
			throw new AccountServiceException("User Id is missing");
		}

		VUser user = null;
		try {
			user = vuserJpaRepo.getOne(id);
			if (user == null) {
				log.warn("Cannot find user's information: " + id);
			}

		} catch (DataAccessException dae) {
			log.error(DAE + ": " + dae.getMessage() + " " + dae.getCause());
			throw new AccountServiceException(DAE, dae);
		}
		return user;
	}

	/**
	 * This method returns the user details after validating that loggendIn user
	 * is authorized to do so
	 * 
	 * @param loggedInUser
	 * @param userid
	 */
	@Override
	public VUserdto getUserDetails(String loggedInUser, Long userid) {

		List<VUser> users = vuserJpaRepo.findByUsernameIgnoreCaseAndIsactiveTrueAndStatusTrue(loggedInUser);
		VUser loggedIn = null;
		if(!CollectionUtils.isEmpty(users))
			loggedIn = users.get(0);
		VUser userDetails = vuserJpaRepo.getOne(userid);
		// Get User Role and Tenant Id and return VUserdto
		if (isPermitted(loggedIn, userDetails)) {
			VUserdto userDto = DtoEntityMapper.getDecoupledUser(userDetails);
			userDto.setUsertofeaturepermission(getUserPermissions(userDetails.getId()));
			Tenant atenant = tenantJpaRepo.findByTenantid(userDetails.getTenantid()).get(0);
			userDto.setTenantId(atenant.getTenantid());
			userDto.setTenantname(atenant.getName());
			return userDto;
		} else {
			return null;
		}
	}
	
	private Map<String, List<String>> getUserPermissions(Long userId){
		
		List<NameValuePair> featureIds = usertofeaturepermissionJpaRepo.findByUserId(userId);
		Map<String,List<String>> usertofeaturepermission = new HashMap<>();
		featureIds.forEach(featureId -> {
			List<String> permissionList = usertofeaturepermissionJpaRepo.findUsertofeaturepermissionByUserIdAndFeatureId(userId,Long.parseLong(featureId.getValue().toString()));
			usertofeaturepermission.put(featureId.getKey(), permissionList);
		});
		return usertofeaturepermission;
	}
	/**
	 * @param tenantId
	 */
	@Override
	public List<VUserdto> getAllUserDetails(UUID tenantId, String tenantType) {
		List<VUser> users=null;
		List<VUserdto> userDtoList = new ArrayList<>();
		
		if(StringUtils.equals(tenantType, FusionConstants.TENANTTYPE_CSP))
			users = vuserJpaRepo.findAllByIsactiveTrueAndStatusTrueAndTenantId(tenantId);
		else
			users = vuserJpaRepo.findByTenantidAndIsactiveTrueAndStatusTrue(tenantId);
		
		log.debug("Returned User List size {}", users.size());
		if(!CollectionUtils.isEmpty(users)) {
			for(VUser userDetails:users) {
				VUserdto userDto = DtoEntityMapper.getDecoupledUser(userDetails);
				Tenant atenant = tenantJpaRepo.findByTenantid(userDetails.getTenantid()).get(0);
				userDto.setTenantId(atenant.getTenantid());
				userDto.setTenantname(atenant.getName());
				userDtoList.add(userDto);
			}
			return userDtoList;
		} 
		else
			return Collections.emptyList();
	}
	
	
	/**
	 * This method updates the user isAtive to false, this soft deleting the
	 * user
	 * 
	 * @param id
	 */
	@Transactional(rollbackFor=Exception.class)
	@Override
	public boolean delete(String loggedInUserName, Long id) {
		log.debug("Entering FusionUserAccountService::delete");

		boolean ret = false;
		
		if ((loggedInUserName != null) && (id != null)) {
			VUser loggedInUser = findVUser(loggedInUserName);
			VUser userToDelete = findVUser(id);
			log.debug("LoggedIn(Parent) Tenantid: " + loggedInUser.getTenantid());
			log.debug("userToDelete Tenantid: " + userToDelete.getTenantid());

			if ((!loggedInUser.getId().equals(id)) && (isPermitted(loggedInUser, userToDelete))) {
				VUser vuser = vuserJpaRepo.getOne(id);
				if (vuser == null) 
					ret = false;
				 else {
					Usercredential uc = ucJpaRepo.findByUserId(vuser.getId());
					if (uc != null) {
						uc.setIsactive(false);
						ucJpaRepo.save(uc);
					}
					int count = usertofeaturepermissionJpaRepo.countByUserId(id);
					if(count>0) {
						log.debug("user {} exist in usertofeaturepermission",id);
						usertofeaturepermissionJpaRepo.deleteUserpermissionByUseridAndTenantid(id);
						usertofeaturepermissionJpaRepo.flush();
					}
					//Soft delete user alert notification TRPL-1410
					UserNotification un = userNotificationRepository.findByUserIdAndIsactiveTrue(vuser.getId());
					 if(un!=null) {
						log.debug("Alert notification configuration for userId {} exist in usernotification",un.getUserId());
						un.setIsactive(false);
						userNotificationRepository.save(un);
					 }
						 
					vuser.setIsactive(false);
					vuserJpaRepo.save(vuser);
					ret = true;
				}
			}
		}

		log.debug("Exiting FusionUserAccountService::delete");
		return ret;
	}

	@Override
	@Transactional (rollbackFor=Exception.class)
	public VUser create(String loggedInUserName, VUser createUser) {
		log.debug("Inside FusionUserAccountService::create User method");
			List<VUser> users = vuserJpaRepo.findByEmailIgnoreCaseAndIsactiveTrue(createUser.getEmail());
			if (users.isEmpty()) {
				VUser user = vuserJpaRepo.saveAndFlush(createUser);
				log.debug("User is created for {}",user.getId());
				log.info("User is created with email {}",user.getUsername());
				return user;
			}
		return null;
	}
	
	@Override
	@Transactional
	public void updatePermission(VUser vuser, Map<String,List<String>> permissionMap) {
		int count = usertofeaturepermissionJpaRepo.countByUserId(vuser.getId());
		if(count>0) {
			log.debug("user {} exist in usertofeaturepermission",vuser.getId());
			usertofeaturepermissionJpaRepo.deleteUserpermissionByUseridAndTenantid(vuser.getId());
			usertofeaturepermissionJpaRepo.flush();
			log.debug("set Permission for user Id {}",vuser.getId());
			
			if(permissionMap!=null) {
				permissionMap.forEach((k,v) ->{	
					Tpfeature tf = tpfeatureJpaRepo.findByName(k);
					List<Tppermission> tpList = tppermissionJpaRepo.findByName(v);
					tpList.forEach(tp -> {
						savePermission(vuser,tf,tp);
					});
			 });
		  }
		}else {
			log.debug("set Permission for user Id {}",vuser.getId());			
			if(permissionMap!=null) {
				permissionMap.forEach((k,v) ->{	
					Tpfeature tf = tpfeatureJpaRepo.findByName(k);
					List<Tppermission> tpList = tppermissionJpaRepo.findByName(v);
					tpList.forEach(tp -> {
						savePermission(vuser,tf,tp);
					});
			 });
		  }
		}
	}
	
	@Override
	@Transactional
	public void createPermission(VUser vuser, Map<String, List<String>> permissionMap) {

		if (permissionMap != null) {
			permissionMap.forEach((k, v) -> {
				Tpfeature tf = tpfeatureJpaRepo.findByName(k);
				List<Tppermission> tpList = tppermissionJpaRepo.findByName(v);
				tpList.forEach(tp -> {
					savePermission(vuser, tf, tp);
				});
			});
		}
		log.info("User Permission is added  {}", vuser.getUsername());
	}
 
	 private void savePermission(VUser vuser,Tpfeature tf, Tppermission tp ) {
		 Usertofeaturepermission permission = new Usertofeaturepermission();
			permission.setUserId(vuser);
			permission.setFeatureId(tf);
			permission.setPermissionId(tp);
			permission.setTenantid(vuser.getTenantid());
			permission.setIsactive(true);
			usertofeaturepermissionJpaRepo.saveAndFlush(permission);
	 }
	
	@Transactional(rollbackFor=Exception.class)
	@Override
	public Map<String, Object> update(String loggedInUserName, VUser updateUser) {
		log.debug("Entering FusionUserAccountService::update");

		int countEmail = vuserJpaRepo.findCountByEmailAndId(updateUser.getEmail().toLowerCase(), updateUser.getId());
		Map<String, Object> ret = new HashMap<>();

		if (countEmail != 0) {
			ret.put(VUSER, null);
			ret.put(ERROR, new FusionMessage("0015", MessageUtil.getMessage("email.alreadyexists.0015"), true));
			return ret;
		}

		Tenant updateUserTenant = null;
		log.debug("Tenant Id: " + updateUser.getTenantid());
		List<Tenant> tenants = tenantJpaRepo.findByTenantid(updateUser.getTenantid());
		
		if (!tenants.isEmpty()) {
			updateUserTenant = tenants.get(0);
		} else {
			log.error("Error updating user: " + updateUser.getUsername());
			throw new AccountServiceException("Error updating user: " + updateUser.getUsername());
		}
		
		Tenant loggedInUserTenant = null;
		VUser loggedInUser = findVUser(loggedInUserName);
		if (loggedInUser != null)
			tenants = tenantJpaRepo.findByTenantid(loggedInUser.getTenantid());

		if (!tenants.isEmpty()) {
			loggedInUserTenant = tenants.get(0);
		} else {
			if (loggedInUser != null)
			{
			log.error("Error getting logged in user's tenant information: " + loggedInUser.getUsername());
			throw new AccountServiceException(
					"Error getting logged in user's tenant information: " + loggedInUser.getUsername());
			}
		}

		VUser updatedUser = null;
		ret = new HashMap<>();

		boolean duplicateEmail = false;
		VUser toUpdateUser = vuserJpaRepo.getOne(updateUser.getId());

		if ((loggedInUserTenant!=null && (loggedInUserTenant.getTenantid().toString().equals(updateUserTenant.getTenantid().toString())))
				||(loggedInUser!=null && (loggedInUser.getId().longValue() == toUpdateUser.getId().longValue()))
				|| (loggedInUserTenant!=null && (loggedInUserTenant.getId().longValue() == updateUserTenant.getParenttenantId().longValue()))) {

			populateToUpdateUser(updateUser, toUpdateUser);
			updatedUser = vuserJpaRepo.save(toUpdateUser);
			updatedUser.setTenant(updateUserTenant);
			ret.put(VUSER, updateUser);
			ret.put(ERROR, null);
			return ret;
		}

		List<VUser> users = vuserJpaRepo.findByEmailIgnoreCaseAndIsactiveTrue(updateUser.getEmail());
		if (CollectionUtils.isEmpty(users)) {
			duplicateEmail = false;
		} else if (!users.get(0).getId().equals(updateUser.getId())) {
			duplicateEmail = true;
		}

		if (duplicateEmail) {
			ret.put(VUSER, null);
			ret.put(ERROR, new FusionMessage("0015", MessageUtil.getMessage("email.alreadyexists.0015"), true));
			return ret;
		}

		populateToUpdateUser(updateUser, toUpdateUser);
		updatedUser = vuserJpaRepo.save(toUpdateUser);
		updatedUser.setTenant(updateUserTenant);
		ret.put(VUSER, updateUser);
		ret.put(ERROR, null);
		log.debug("Exiting FusionUserAccountService::update");
		return ret;
	}

	/**
	 * 
	 * @param loggedInUser
	 * @param workOnUser
	 * @return
	 */
	public boolean isPermitted(VUser loggedInUser, VUser workOnUser) {

		boolean allow = false;
		Tenant aWorkOnUserTenant = null;
		Tenant loggedInUserTenant = null;

		try { // Get valid values
			if (workOnUser != null) {
				aWorkOnUserTenant = tenantService.findOne(workOnUser.getTenantid());
			} else {
				log.error("workOnUser is null.");
				return allow;
			}
			if (loggedInUser != null) {
				loggedInUserTenant = tenantService.findOne(loggedInUser.getTenantid());
			} else {
				log.error("loggedInUser is null.");
				return allow;
			}

		} catch (Exception e) {
			log.error("Tenantid is not found.");
			log.error(ERROR_MSG + ": " + e.getMessage() + "\n" + e.getCause());
			return allow;
		}

		// Ensures that the logged in user is allowed to delete the user
		log.debug("Child's Parent Tenant Id: " + aWorkOnUserTenant.getParenttenantId());
		log.debug("LoggedIn(Parent) Tenant Id: " + loggedInUserTenant.getId());
		if (aWorkOnUserTenant.getTenantid().equals(loggedInUserTenant.getTenantid()) || 
				aWorkOnUserTenant.getParenttenantId().longValue() == loggedInUserTenant.getId().longValue()) {
			allow = true;
		}
		return allow;
	}


	private void populateToUpdateUser(VUser updateUser, VUser toUpdateUser) {
		toUpdateUser.setAccountlockedtime(updateUser.getAccountlockedtime());
		toUpdateUser.setEmail(updateUser.getEmail());
		toUpdateUser.setFirstname(updateUser.getFirstname());
		// userdto.setUserId(user.getId());
		toUpdateUser.setAuthenticationtypeId(updateUser.getAuthenticationtypeId());
		toUpdateUser.setIsactive(updateUser.getIsactive());
		toUpdateUser.setIslocked(updateUser.getIslocked());
		toUpdateUser.setLastloginfailuretime(updateUser.getLastloginfailuretime());
		toUpdateUser.setLastname(updateUser.getLastname());
		toUpdateUser.setLoginfailurecount(updateUser.getLoginfailurecount());
		toUpdateUser.setLoginfailureip(updateUser.getLoginfailureip());
		toUpdateUser.setMiddlename(updateUser.getMiddlename());
		toUpdateUser.setStatus(updateUser.isStatus());
		toUpdateUser.setTenantid(updateUser.getTenantid());
		toUpdateUser.setUsername(updateUser.getEmail());
		toUpdateUser.setPhoneNumber(updateUser.getPhoneNumber());
	}
	
    @LogRequest
    @Transactional(readOnly = true)
    @Override
    public UserXsKeyPairResponseDto getUserXsKeyPair(UUID tenantid, String username, String name) {
        if (username == null) {
            log.error("Missing User Name");
            throw new AccountServiceException("Missing User Name");
        }

        List<VUser> users = vuserJpaRepo.findByUsernameIgnoreCaseAndIsactiveTrueAndStatusTrue(username);
        if (users == null || users.isEmpty()) {
            log.error("User not found: " + username);
            throw new AccountServiceException("User not found");
        } else {
            VUser user = users.get(0);
            if (StringUtils.isAnyBlank(user.getXstreamInfo())) {
                log.warn("xStream KeyPair not found for user {}", username);
                return null;
            } else {
                try {
                	
                	@SuppressWarnings("serial")
        			Type typeofobject = new TypeToken<List<ServiceproviderKeyInfoResponseDto>>(){}.getType();
                    List<ServiceproviderKeyInfoResponseDto> dto = JsonUtil.converttoList(user.getXstreamInfo(), typeofobject);
                    log.debug("spdto size {}",dto.size());
                	   List<ServiceproviderKeyInfoResponseDto> filterDto =  dto.stream()	
                			   .filter(d -> ( d.getCloudServiceProvider().equalsIgnoreCase("xstream")|| 
                					   d.getName().equalsIgnoreCase(name)))
                			   .collect(Collectors.toList()); 
                	   if(!filterDto.isEmpty()) {
                		   ServiceproviderKeyInfoResponseDto spdto = filterDto.get(0);
                		   log.debug("cloud service provider name: {}",spdto.getCloudServiceProvider());
                		   return new UserXsKeyPairResponseDto(spdto.getPublicKey(),
                				   encryptionService.decrypt(spdto.getPrivateKey(), tenantid));
                	   }
                	   
                	   return null;
//                    return new UserXsKeyPairResponseDto(user.getXskey(),
//                            encryptionService.decrypt(user.getXssecret(), tenantid));
                } catch (Exception e) {
                    log.error("Error encountered decrypting KeyPair for user {}", username);
                    log.error("Error info: " + e.getMessage() + "\n" + e.getCause());
                    throw new AccountServiceException("Error decrypting KeyPair");
                }
            }
        }
    }

	@Override
	@Transactional
	public UserRegistrationTokenValidationDto validateUserRegistrationToken(String token) throws Exception {
		List<VUser> aList = this.vuserJpaRepo.findByRegistrationtoken(token);
		UserRegistrationTokenValidationDto dto = new UserRegistrationTokenValidationDto();
		if (CollectionUtils.isEmpty(aList))
			return dto;
		VUser aVuser = aList.get(0);
		if (aVuser.getRegistrationstatus() == true || FusionCalendarUtil.isPassedMoreThanHours(aVuser.getRegitokenexpirationdate(), 0))
			return dto;
        // to generate QR code if the user have not done yet.

		if (aVuser.isMfaEenable() == false) {
			if (StringUtils.isBlank(aVuser.getMfaCode())) {
				String mfacode = Base32.random(); // Generated google secrets for MFA
				aVuser.setMfaCode(mfacode);
				aVuser = this.vuserJpaRepo.saveAndFlush(aVuser);
			}
			String qrUri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", APP_NAME, aVuser.getEmail(), aVuser.getMfaCode(), APP_NAME);
			String qrUrl = QR_PREFIX + URLEncoder.encode(qrUri, StandardCharsets.UTF_8);
			dto.setQrUrl(qrUrl);
			dto.setMfaCode(aVuser.getMfaCode());
		}
		Tenant aTenant = this.tenantJpaRepo.getTenantByTenantid(aVuser.getTenantid());
	    dto.setValid(true);
	    dto.setEmail(aVuser.getEmail());
	    dto.setMessage("Valid Token");
	    dto.setEmail(aVuser.getEmail());
	    dto.setFirstname(aVuser.getFirstname()==null?"":aVuser.getFirstname());
	    dto.setLastname(aVuser.getLastname()==null?"":aVuser.getLastname());
	    dto.setPhonenumber(aVuser.getPhoneNumber()==null?"":aVuser.getPhoneNumber());
	    dto.setTenantId(aVuser.getTenantid().toString());
	    if (aTenant != null)
	    	dto.setTenantName(aTenant.getName());
	    dto.setId(aVuser.getId());
		return dto;
	}

	@Override
	public void emailUserRegistrationLink(VUser unRegisteredUser) {
		if (unRegisteredUser.getRegistrationstatus() == true) {
			logger.info("{} already registered.", unRegisteredUser.getEmail());
			return;
		}
		String linkString =  generateRegistrationEmailLink(unRegisteredUser);
		log.debug("User Reg. Link {}",linkString);
		MailDTO dto = new MailDTO();
		dto.setSubject("Virtustream Trust Platform User Registration");
		dto.setContent("<p>Please access the following URL to finish your user registration! </p> " + "<p>" + linkString + "</p>" );
		dto.setTo(unRegisteredUser.getEmail());
		Map<String, Object> model = new HashMap<>();
		model.put("username", unRegisteredUser.getEmail());
		model.put("linkString",linkString);
		model.put("expiretime",unRegisteredUser.getRegitokenexpirationdate());
		dto.setModel(model);
		this.mailService.sendEmail(dto,MAIL_TEMPLATE);
		logger.info("Sent user registration email to {}.", dto.getTo());				
	}
	
	/**
     * to generate a temp registration email link string for user registration
     */
	private String generateRegistrationEmailLink(VUser unRegisteredUser) {
		String emailLink = null;
		if (uiServerURL != null && unRegisteredUser.getRegistrationtoken() != null 
			&& unRegisteredUser.getRegistrationstatus() == false
			&& !FusionCalendarUtil.isPassedMoreThanHours(unRegisteredUser.getRegitokenexpirationdate(), 0)) {
			emailLink = uiServerURL + "/register?token=" + unRegisteredUser.getRegistrationtoken();
		}
		return emailLink;
	}

	@Transactional
	public VUserdto saveUserRegistrationInfo(VUserdto userdto ) {
		VUser aUser = vuserJpaRepo.getOne(userdto.getId());
		if ( aUser == null || aUser.getRegistrationstatus() == true)
			return null;
		DtoEntityMapper.updateVuserFromDto(userdto, aUser);
		Collection<Usercredential> usercredentialsCollection = aUser.getUsercredentialsCollection();
		if (CollectionUtils.isEmpty(usercredentialsCollection)) {
			usercredentialsCollection = new ArrayList<> ();
			Usercredential usercredential = new Usercredential();
			usercredential.setPassword(userdto.getPassword());
			usercredential.setUserId(userdto.getId());
			usercredential.setIsactive(true);
			usercredential.setActivateddate(new Date());
			usercredential.setTenantid(aUser.getTenantid());
			usercredentialsCollection.add(usercredential);
			aUser.setUsercredentialsCollection(usercredentialsCollection);
		}
		else {
			// per db design, only one record
			for (Usercredential aUsercredential: usercredentialsCollection  ) {
					aUsercredential.setIsactive(true);
					aUsercredential.setActivateddate(new Date());
					aUsercredential.setDeactivateddate(null);
					aUsercredential.setPassword(userdto.getPassword());
			}			
		}
        // to flag the user is registed
		aUser.setRegistrationstatus(true);
		// to flag the MFA
		aUser.setMfaEenable(userdto.getMfaEenable());
		VUser savedUser = this.vuserJpaRepo.saveAndFlush(aUser);
		if (savedUser.getId() == null) 
			return null;
		VUserdto savedUserdto = new VUserdto();
		try {
			BeanUtils.copyProperties(savedUserdto, savedUser);
			savedUserdto.setTenantId(savedUser.getTenantid());
		} catch (IllegalAccessException | InvocationTargetException e) {
			log.error("Failed to copy saved user info to a dto");
			log.error(ERROR_MSG + ": " + e.getMessage() + "\n" + e.getCause());
			return null;
		}	
		return savedUserdto;
	}

	@Override
	public List<ServiceproviderKeyInfoResponseDto> findServiceProviderKeys(UUID tenantid, String keyId, Long userId,
			String cloud) {
		List<ServiceproviderKeyInfoResponseDto> userCloudDetails = new ArrayList<>();
		log.debug("Inside findServiceproviderkeys service {}", keyId);
		VUser user = vuserJpaRepo.findByIsActiveAndStatus(userId);
		if (StringUtils.isAllBlank(user.getXstreamInfo(), user.getAzureInfo(), user.getGcpInfo())) {
			log.warn("Cloud configuration does not exist for the user {}", userId);
			return userCloudDetails;
		}
		try {
			List<ServiceproviderKeyInfoResponseDto> userAzureInfos = new ArrayList<>();
			List<ServiceproviderKeyInfoResponseDto> userXstreamInfos = new ArrayList<>();
			List<ServiceproviderKeyInfoResponseDto> userGcpInfos = new ArrayList<>();
			@SuppressWarnings("serial")
			Type typeofobject = new TypeToken<List<ServiceproviderKeyInfoResponseDto>>() {
			}.getType();
			if (StringUtils.isNotEmpty(user.getXstreamInfo())) {
				userXstreamInfos = JsonUtil.converttoList(user.getXstreamInfo(), typeofobject);
				userXstreamInfos.forEach(d -> {
					d.setPrivateKey("");
				});
			}
			if (StringUtils.isNotEmpty(user.getAzureInfo())) {
				userAzureInfos = JsonUtil.converttoList(user.getAzureInfo(), typeofobject);
			}
			if (StringUtils.isNotEmpty(user.getGcpInfo())) {
				userGcpInfos = JsonUtil.converttoList(user.getGcpInfo(), typeofobject);
			}
			if (keyId.equalsIgnoreCase("all")) {
				userCloudDetails.addAll(Stream
						.of(userGcpInfos.stream().filter(d -> StringUtils.equals(d.getTenantId(), tenantid.toString()))
								.collect(Collectors.toList()), userAzureInfos.stream().filter(a -> StringUtils.equals(a.getTenantId(), tenantid.toString()))
								.collect(Collectors.toList()), userXstreamInfos)
						.filter(Objects::nonNull).flatMap(Collection::stream).collect(Collectors.toList()));
				userCloudDetails.forEach(d -> {
					if (StringUtils.isNotEmpty(d.getPublicKey()))
						d.setPublicKey(FusionStringUtil.replaceWithDot(d.getPublicKey()));
					if (StringUtils.isNotEmpty(d.getSubscriptionid()))
						d.setSubscriptionid(FusionStringUtil.replaceWithDot(d.getSubscriptionid()));
				});

			} else if (StringUtils.isNotEmpty(cloud)) {
				if (StringUtils.equalsIgnoreCase(CSPType.GCP.getValue(), cloud)) {
					userCloudDetails = userGcpInfos.stream().filter(Objects::nonNull).collect(Collectors.toList());
				} else if (StringUtils.equalsIgnoreCase(CSPType.AZURE.getValue(), cloud)) {
					userCloudDetails = userAzureInfos.stream().filter(Objects::nonNull).collect(Collectors.toList());
				} else if (StringUtils.equalsIgnoreCase(CSPType.XSTREAM.getValue(), cloud)) {
					userCloudDetails = userXstreamInfos.stream().filter(Objects::nonNull).collect(Collectors.toList());
				}
				userCloudDetails = userCloudDetails.stream().filter(d ->StringUtils.equals(d.getId(), keyId))
						.collect(Collectors.toList());
			} else {
				log.info("Cloud is empty for the provided key <{}>", keyId);
				return userCloudDetails;
			}
			if (CollectionUtils.isNotEmpty(userGcpInfos)) {
				log.info("GCP configuration found for user {}", userId);
			}
			if (CollectionUtils.isNotEmpty(userAzureInfos)) {
				log.info("Azure configuration found for user {}", userId);
			}
			if (CollectionUtils.isNotEmpty(userXstreamInfos)) {
				log.info("Xstream configuration found for user {}", userId);
			}
		} catch (Exception e) {
			log.error("Error encountered in findSPInfo: " + e.getMessage() + "\n" + e.getCause());
		}

		return userCloudDetails;
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public FusionMessage updateServiceProviderKey(List<ServiceproviderKeyInfoResponseDto> spdtos, UUID tenantid, Long id) {
		
		FusionMessage msg=null;
		CloudServiceProviderClient cspclient = cspclientfactory.getCSPClient(spdtos.get(0).getCloudServiceProvider());
		msg = cspclient.updateServiceProviderKey(spdtos, tenantid, id);
		return msg;
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public FusionMessage deleteServiceProviderKey(Long userId, String key, String cloudServiceProvider) {
		VUser user = vuserJpaRepo.findByIsActiveAndStatus(userId);
		@SuppressWarnings("serial")
		Type typeofobject = new TypeToken<List<ServiceproviderKeyInfoResponseDto>>() {
		}.getType();
		List<ServiceproviderKeyInfoResponseDto> userCloudDetails = new ArrayList<>();

		try {
			if (cloudServiceProvider.equalsIgnoreCase(CSPType.XSTREAM.getValue())) {
				if (!StringUtils.isEmpty(user.getXstreamInfo())) {
					userCloudDetails = JsonUtil.converttoList(user.getXstreamInfo(), typeofobject);
					userCloudDetails = userCloudDetails.stream()
							.filter(dto -> !dto.getId().equalsIgnoreCase(key)).collect(Collectors.toList());
					user.setXstreamInfo(JsonUtil.convertListtoJsonString(userCloudDetails));
					userridService.deleteByKeypairid(userId, key);
					vuserJpaRepo.saveAndFlush(user);
					return new FusionMessage(null, MessageUtil.getMessage(DELETE_SUCCESSFUL_MSG), false);
				}
			} else if (cloudServiceProvider.equalsIgnoreCase(CSPType.AZURE.getValue())) {
				if (!StringUtils.isEmpty(user.getAzureInfo())) {
					userCloudDetails = JsonUtil.converttoList(user.getAzureInfo(), typeofobject);
					String selectedTenantId;
					if (CollectionUtils.isNotEmpty(userCloudDetails)) {
						List<ServiceproviderKeyInfoResponseDto> selectedTenantList;
						selectedTenantList = userCloudDetails.stream()
								.filter(dto -> StringUtils.equals(dto.getId(), key)).collect(Collectors.toList());
						if (CollectionUtils.isNotEmpty(selectedTenantList)) {
							selectedTenantId = selectedTenantList.get(0).getTenantId();
							selectedTenantList = userCloudDetails.stream()
									.filter(dto -> StringUtils.equals(dto.getTenantId(), selectedTenantId))
									.collect(Collectors.toList());
							userCloudDetails = userCloudDetails.stream()
									.filter(dto -> !StringUtils.equals(dto.getId(), key)).collect(Collectors.toList());
							user.setAzureInfo(JsonUtil.convertListtoJsonString(userCloudDetails));
							if (selectedTenantList.size() == 1) {
								@SuppressWarnings("serial")
								Type refreshTokenType = new TypeToken<List<RefreshTokendto>>() {
								}.getType();
								List<RefreshTokendto> refreshTokendtoList = GsonUtil.getAsType(user.getAzureToken(),
										refreshTokenType);
								refreshTokendtoList = refreshTokendtoList.stream()
										.filter(dto -> !StringUtils.equals(dto.getTenantId(), selectedTenantId))
										.collect(Collectors.toList());
								user.setAzureToken(GsonUtil.toString(refreshTokendtoList));
							}

							vuserJpaRepo.saveAndFlush(user);
							return new FusionMessage(null, MessageUtil.getMessage(DELETE_SUCCESSFUL_MSG), false);
						}
					}
				}
			} else if (cloudServiceProvider.equalsIgnoreCase(CSPType.GCP.getValue())) {
				log.debug("GCP Info key for {}={}", user.getUsername(), user.getGcpInfo());
				if (StringUtils.isNotEmpty(user.getGcpInfo())) {
					userCloudDetails = JsonUtil.converttoList(user.getGcpInfo(), typeofobject);
					userCloudDetails = userCloudDetails.stream()
							.filter(dto -> !dto.getId().equalsIgnoreCase(key)).collect(Collectors.toList());
					user.setGcpInfo(JsonUtil.convertListtoJsonString(userCloudDetails));
					if (CollectionUtils.isEmpty(userCloudDetails))
						user.setGcpToken(null);
					vuserJpaRepo.saveAndFlush(user);
					log.info("Gcp info with id <{}> deleted successfully for user id <{}>", key, userId);
					return new FusionMessage(null, MessageUtil.getMessage(DELETE_SUCCESSFUL_MSG), false);
				}
			}

		} catch (Exception ex) {
			log.error("SP key deletion failed for user {}", userId);
			log.error(ERROR_MSG + ex.getMessage() + "\n" + ex.getCause());
			return new FusionMessage(null, MessageUtil.getMessage("delete.unsuccessful.msg"), true);
		}
		return null;
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public Date extendRegistrationTokenDate(Long userId, int days) {
		VUser aUser = this.findVUser(userId);
		if (aUser.getRegistrationtoken() == null || aUser.getRegitokenexpirationdate() == null ) { 
			logger.error("The user does not have registration token: {}", userId);
			return null;
		}	
		aUser.setRegitokenexpirationdate(new Timestamp(FusionCalendarUtil.addDaysTo(new Date(), days).getTime()));
		VUser saveUser = this.vuserJpaRepo.save(aUser);
		return saveUser.getRegitokenexpirationdate();
	}
	
	/**
	 * 
	 * To extend registration token to 7 more days and send out the email again.
	 */
	@Override
	public boolean resendRegistrationTokenEmail(Long userId, int tokenExtendDays) {
		VUser aUser = this.findVUser(userId);
		if (aUser.getRegistrationtoken() == null || aUser.getRegitokenexpirationdate() == null ) { 
			logger.error("The user does not have a registration token: {}", userId);
			return false;
		}
		if (aUser.getRegistrationstatus()) {
			logger.info("The user is registered: {}", userId);
			return false;
		}
		aUser.setRegitokenexpirationdate(new Timestamp(FusionCalendarUtil.addDaysTo(new Date(), tokenExtendDays).getTime()));
		VUser saveUser = vuserJpaRepo.save(aUser);
		try{
			emailUserRegistrationLink(saveUser);
		} catch (Exception e) {
			logger.error("Error in sending email: {}", e.getMessage());
			return false;
		}
		return true;
	}

	@Override
	public FusionMessage forgotPassword(String email, int days) {
		VUser user = this.findVUser(email);
		FusionMessage fm=null;
		try {
		 
		if (user != null) {
			if(!user.getRegistrationstatus()) {
				return new FusionMessage(null, MessageUtil
						.getMessage("notificationservice.forgotPasswordInvalidate.notregister.msg"), true);
			 }
			user.setForgotpwdtokenexpirationdate(new Timestamp(FusionCalendarUtil.addDaysTo(new Date(), days).getTime()));
			user.setForgotpwdtoken(RandomKeyGenerator.generateRandomBase64Token());
			user.setForgotpwdstatus(false);
			VUser saveUser = this.vuserJpaRepo.save(user);
			this.forgotPasswordEmailLink(saveUser);
		}else
			return new FusionMessage(null, MessageUtil
					.getMessage("notificationservice.forgotPasswordInvalidate.fail.msg"), true);
		}catch(Exception e) {
			return new FusionMessage(null, MessageUtil
					.getMessage("notificationservice.forgotPasswordRequest.error"), true);
		}
		return fm;
	}
	
	private void forgotPasswordEmailLink(VUser user) {
		String linkString =  generateForgotPasswordEmailLink(user);
		log.debug("Forgot Password Link {}",linkString);
		MailDTO dto = new MailDTO();
		dto.setSubject("Virtustream Trust Platform Forgot Password");
		dto.setContent("<p>Please access the following URL to reset your password </p> " + "<p>" + linkString + "</p>" );
		dto.setTo(user.getEmail());
		this.mailService.sendEmail(dto,null);
		logger.info("Forgot password link email to {}", dto.getTo());				
	}
	
	/**
     * to generate a forgotpassword email link string for user registration
     */
	private String generateForgotPasswordEmailLink(VUser user) {
		String emailLink = null;
		if (uiServerURL != null && user.getForgotpwdtoken() != null 
			&& user.getForgotpwdstatus() == false
			&& !FusionCalendarUtil.isPassedMoreThanHours(user.getForgotpwdtokenexpirationdate(), 0)) {
			emailLink = uiServerURL + "/forgotpassword?token=" + user.getForgotpwdtoken();
		}
		return emailLink;
	}
	
	@Override
	@Transactional
	public ForgotPasswordTokenValidationDto validateForgotPasswordToken(String token) {
		List<VUser> aList = this.vuserJpaRepo.findByForgotpwdtokenAndRegistrationstatusTrueAndIsactiveTrue(token);
		ForgotPasswordTokenValidationDto dto = new ForgotPasswordTokenValidationDto();
		if (CollectionUtils.isEmpty(aList)) {
			logger.error("Forgotpassword : User not exist/registered or invalid token!!");
			return dto;
		}
		VUser aVuser = aList.get(0);
		if (aVuser.getForgotpwdstatus() == true || FusionCalendarUtil.isPassedMoreThanHours(aVuser.getForgotpwdtokenexpirationdate(), 0))
			return dto;
	    dto.setValid(true);
	    dto.setMessage("Valid Token");
	    dto.setId(aVuser.getId());
	    dto.setEmail(aVuser.getUsername());
		return dto;
	}
	
	/**
	 * 
	 * @param userName
	 * @param changedPassword
	 */
	@Override
	@Transactional
	public FusionMessage resetPassword(Long id, String email, String changedPassword) {
		logger.debug("FusionUserAccountServerImpl::resetPassword for userId {}",id);
		FusionMessage fm=null;
		try {
			if (id==null || StringUtils.isAnyEmpty(email, changedPassword)) {
				logger.error(" ResetPassword :: userId/email or changed passsword is null");
				throw new AccountServiceException("userId or changed passsword is null");
			}
			VUser vUser =  this.vuserJpaRepo.findByIdAndUsernameAndRegistrationstatusTrueAndIsactiveTrue(id, email);
			if(vUser==null) {
				logger.error("Resetpassword :: User not exist/registered!!");
				return new FusionMessage("0005",
						MessageUtil.getMessage("IdIsNotFound.0005"), true);
			}
			vUser.getUsercredentialsCollection().iterator().next().setPassword(changedPassword);
			vUser.setLastpasswordchangedate(new Date());
			vUser.setForgotpwdstatus(true);
			vuserJpaRepo.save(vUser);
			logger.debug("ResetPassword for userId {} Success.",id);
			fm = new FusionMessage(null,
					MessageUtil.getMessage("notificationservice.resetPassword.successful.msg"), false);
		}catch(Exception e) {
			logger.error("Error while reset password: {}.",e.getMessage());
			fm = new FusionMessage(null,
					MessageUtil.getMessage("notificationservice.resetPassword.fail.msg"), true);
		}
		return fm;
	}
	
	@Override
	public FusionMessage processAuthCode(AuthCodeDto authCodeDto, UUID loggedInTenantId, String cloud, Long userId) throws Exception {
		VUser user = vuserJpaRepo.getOne(userId);
		if (user == null) {
			log.warn("No user found with userId <{}>", userId);
			throw new ConstraintViolationException("Invalid user id", null);
		}
		
		if (StringUtils.equalsIgnoreCase(CSPType.GCP.getValue(), cloud)) {
			List<Tenant> tenant = tenantJpaRepo.findByTenantid(loggedInTenantId);
			if (CollectionUtils.isEmpty(tenant)) {
				log.warn("No tenant found with tenantId <{}>", loggedInTenantId);
				throw new ConstraintViolationException("Invalid tenant id", null);
			}
			
			CspInfoDto[] gcpInfoArr = GsonUtil.getAsType(tenant.get(0).getGcpInfo(), CspInfoDto[].class);
			if (ArrayUtils.isNotEmpty(gcpInfoArr)) {
				// Considering there will be single GCP config available at Tenant level
				CspInfoDto gcpInfo = gcpInfoArr[0];
				String clientSecret = encryptionService.decrypt(gcpInfo.getClientsecret(), loggedInTenantId);
				GCPTokenDto tokenDto = gcpAuthApi.getAppTokensByAuthCode(gcpInfo.getClientid(),
						clientSecret, authCodeDto.getCode());
				log.debug("Tokens retrieved from GCP for userId <{}>", userId);
				user.setGcpToken(tokenDto.getRefreshToken());
				vuserJpaRepo.save(user);
			} else {
				log.warn("GCP info for the tenantId <{}> is empty", loggedInTenantId);
				throw new FusionException("1022", "gcpinfo.notfound.msg.1022",
						
						MessageUtil.getMessage("gcpinfo.notfound.msg.1022"));
			}
		} else if (StringUtils.equalsIgnoreCase(CSPType.AZURE.getValue(), cloud)) {
			UUID tenantId = UUID.fromString(authCodeDto.getTenantId());
			List<Tenant> tenant = tenantJpaRepo.findByTenantid(tenantId);
			if (CollectionUtils.isEmpty(tenant)) {
				log.warn("No tenant found with tenantId <{}>", tenantId);
				throw new ConstraintViolationException("Invalid tenant id", null);
			}
			azureService.getAzureAccessToken(authCodeDto.getCode(), tenantId, userId);
		}
		
		return new FusionMessage("", "Authorization code processed successfully", false);
	}
	
	@Override
	public Map<String, Boolean> checkRefreshToken(Long userId, UUID tenantId, UUID selectedTenantId, String cloud)
			throws Exception {
		logger.debug("FusionUserAccountServerImpl::Find getRefreshToken for userId {}", userId);
		Map<String, Boolean> cloudTokenMap = new HashMap<>();
		cloudTokenMap.put(ACCESS_TOKEN_EXISTS, false);
		if (StringUtils.equalsIgnoreCase(CSPType.AZURE.getValue(), cloud)) {
			String azureRefreshToken = vuserJpaRepo.findAzureToken(userId);
			@SuppressWarnings("serial")
			Type typeofobject = new TypeToken<List<RefreshTokendto>>() {
			}.getType();
			List<RefreshTokendto> refreshTokendtoList = GsonUtil.getAsType(azureRefreshToken, typeofobject);
			if (CollectionUtils.isNotEmpty(refreshTokendtoList)) {
				refreshTokendtoList = refreshTokendtoList.stream()
						.filter(e -> StringUtils.equals(e.getTenantId(), selectedTenantId.toString()))
						.collect(Collectors.toList());

				if (CollectionUtils.isNotEmpty(refreshTokendtoList)) {
					try {
						String azureAccessToken = azureService.getAzureAccessToken(StringUtils.EMPTY, selectedTenantId,
								userId);
						if (StringUtils.isNotBlank(azureAccessToken)) {
							cloudTokenMap.put(ACCESS_TOKEN_EXISTS, true);
						}
					} catch (MsalInteractionRequiredException msalException) {
						log.error("Azure token expired for the user id <{}>. Re-login required", userId);
					}
				}
			}
		} else if (StringUtils.equalsIgnoreCase(CSPType.GCP.getValue(), cloud)) {
			String gcpRefreshToken = vuserJpaRepo.findGcpToken(userId);
			if (StringUtils.isNotBlank(gcpRefreshToken)) {
				try {
					String gcpAccessToken = gcpService.getGcpAccessToken(tenantId, userId);
					if (StringUtils.isNotBlank(gcpAccessToken)) {
						cloudTokenMap.put(ACCESS_TOKEN_EXISTS, true);
					}
				} catch (GCPAuthenticationException gcpException) {
					log.error("GCP token expired for the user id <{}>. Re-login required", userId);
				}
			}
		}

		return cloudTokenMap;
	}

	/**
	 * Retrieves RIDs of a customer user. If user authenticated via xStreamOne,
	 * extract xStream RIDs from tenant record else extract from userrid fetched
	 * using the xStream cloud configuration setup by the user. Includes GCP/Azure
	 * RIDs as well if available.
	 *
	 * @param tenantid The UUID of the user's tenant
	 * @param userid   The id of the user
	 * @return List of RIDs of a given user
	 */
	@Override
	public List<String> findUserRids(UUID tenantid, Long userid) {
		List<String> xsRids;
		String source = vuserJpaRepo.findSourceById(userid);
		if (StringUtils.equalsIgnoreCase(XSTREAMONE, source)) {
			xsRids = tenantService.findRIDs(tenantid, CSPType.XSTREAM);
		} else {
			xsRids = userridService.findRIDs(userid);
		}
		return Stream
				.of(xsRids, tenantService.findRIDs(tenantid, CSPType.GCP),
						tenantService.findRIDs(tenantid, CSPType.AZURE),
						tenantService.findRIDs(tenantid, CSPType.APEX))
				.flatMap(List::stream).map(rid -> rid).distinct().collect(toList());
	}

}
	