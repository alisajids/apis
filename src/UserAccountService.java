
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface UserAccountService {

	UserXsKeyPairResponseDto getUserXsKeyPair(UUID tenantid, String username, String name);
	VUser findVUser(String userName);
	void cleanUserLoginFailureCount(String userName);
	boolean  recordUserLoginFailures(String userName, String fromIPaddress);
	List<ServiceproviderKeyInfoResponseDto> findServiceProviderKeys(UUID tenantid, String uniqueid, Long userid, String cloud);
	FusionMessage updateServiceProviderKey(List<ServiceproviderKeyInfoResponseDto> spdto, UUID tenantid,Long id);
	FusionMessage deleteServiceProviderKey(Long id, String key,String cloudServiceProvider);
	UserRegistrationTokenValidationDto validateUserRegistrationToken (String token) throws Exception;
	void emailUserRegistrationLink(VUser unRegisterUser );
	VUserdto saveUserRegistrationInfo(VUserdto userdto );
	public void createPassword(String userName, String createPassword);
	VUserdto getUserDetails(String loggedInUser, Long userid);
	List<VUserdto> getAllUserDetails(UUID tenantId, String cspType);
	public boolean delete(String loggedInUserName, Long id);
	public VUser create(String loggedInUserName, VUser createUser);
	public void createPermission(VUser createUser, Map<String,List<String>> permissionMap);
	public void updatePermission(VUser vuser, Map<String,List<String>> permissionMap);
	public Map<String, Object> update(String loggedInUserName, VUser createUser);
	Date extendRegistrationTokenDate(Long userId, int days);
	boolean resendRegistrationTokenEmail(Long userId, int tokenExtendDays);
	FusionMessage forgotPassword(String email, int days);
	ForgotPasswordTokenValidationDto validateForgotPasswordToken (String token);
	public FusionMessage resetPassword(Long id, String email, String changedPassword);
	Map<String, Boolean> checkRefreshToken(Long userId, UUID tenantId, UUID selectedTenantId, String cloud) throws Exception;
	FusionMessage processAuthCode(AuthCodeDto authCodeDto, UUID loggedInTenantId, String cloud, Long userId) throws Exception;
	List<String> findUserRids(UUID tenantid, Long userid);

}
