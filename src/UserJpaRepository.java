
package com.example.common.db.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;


@RepositoryRestResource(exported=false)
public interface UserJpaRepository extends JpaRepository<VUser, Long> {

	@Override
	@Query(" SELECT u FROM VUser u WHERE u.isactive = true and u.id =:id")
	VUser getOne(@Param("id") Long id);
	
	@Query(" SELECT u FROM VUser u WHERE u.isactive=true And u.status=true and u.id=:id")
	VUser findByIsActiveAndStatus(@Param("id") Long id);

	@Query(" SELECT u FROM VUser u WHERE u.isactive = true and u.id =:id and tenantid = :tenantid ")
	VUser findOneUser(@Param("id") Long id, @Param("tenantid") UUID tenantid);

	@Query(" SELECT u FROM VUser u WHERE u.isactive = true and  Lower(u.username)= :username  ")
	VUser findUser(@Param("username") String username);
	
	@Query(value = "SELECT v.* FROM VUser v " + 
			"INNER JOIN Tenant t ON v.tenantid = t.tenantid "+
			"WHERE t.isactive = true " + 
			"AND v.isactive = true " + 
			"AND v.status = true " + 
//			"and (v.registrationstatus=true or v.registrationstatus is null) "+
			"AND v.tenantid in ( " + 
			"SELECT tt.tenantid FROM tenant tt where tt.tenantid=:tenantid "+ 
			"OR tt.parenttenant_id = ( SELECT t1.id FROM tenant t1 WHERE t1.tenantid=:tenantid)) "+ 
			"ORDER by v.username asc", nativeQuery=true)
	List<VUser> findAllByIsactiveTrueAndStatusTrueAndTenantId(@Param("tenantid") UUID tenantid);
	
	List<VUser> findByTenantidAndIsactiveTrueAndStatusTrue(UUID tenantid );
	List<VUser> findByUsernameIgnoreCaseAndIsactiveTrueAndStatusTrue(String username );
	List<VUser> findByUsernameIgnoreCaseAndIsactiveTrue(String username );
	List<VUser> findByEmailIgnoreCaseAndIsactiveTrue(String email );
	List<VUser> findByUsernameIgnoreCaseAndTenantid(String username, UUID tenantid);
	List<VUser> findByRegistrationtoken(String registrationtoken);
	List<VUser> findByForgotpwdtokenAndRegistrationstatusTrueAndIsactiveTrue(String forgotpwdtoken);
	VUser findByIdAndUsernameAndRegistrationstatusTrueAndIsactiveTrue(Long id,String username);
	VUser findByUsernameAndRegistrationstatusTrueAndIsactiveTrue(String username);


	
	@Query("SELECT u FROM VUser u where LOWER(u.username) = LOWER(:username) and u.tenantid = :tenantid and u.isactive = true")
	VUser findAllByUsernameAndTenantid(@Param("username") String username, @Param("tenantid") UUID tenantid);

	@Query("select count(v.id) from VUser v where Lower(v.username)=:username and v.id<>:id and v.isactive='true' ")
	int findCountByUserNameAndId(
			@Param("username") String username,
			@Param("id") Long id);

	@Query("select count(v.id) from VUser v where Lower(v.email)=:email and v.id<>:id and v.isactive='true' ")
	int findCountByEmailAndId(
			@Param("email") String email,
			@Param("id") Long id);

	@Modifying
	@Query("update VUser set status = false WHERE tenantid = :tenantid ")
	void disableByTenantid(@Param("tenantid") UUID tenantid);

	@Modifying
	@Query("update VUser set status = true WHERE tenantid = :tenantid ")
	void enableByTenantid(@Param("tenantid") UUID tenantid);

	//	@Cacheable(value="vuserCache")
	@Query("SELECT u.email FROM VUser u WHERE u.isactive=true and u.username=?1")
	String getEmailAddressForUser(String userName);

	@Query("SELECT u.tenantid FROM VUser u WHERE u.isactive=true and u.username=?1")
	UUID getTenantForUser(String userName);

	Page<VUser> findByStatus(@Param("status") boolean status,Pageable pageable);

	@Modifying
	@Query("update VUser set isActive = false WHERE tenantid = :tenantid and isActive = true")
	void deactiveByTenantid(@Param("tenantid") UUID tenantid);

	@Query("SELECT u FROM VUser u WHERE u.tenantid=?1 AND u.isactive=true")
	public List<VUser> getUserByTenantidAndIsactiveTrue(UUID tenantid);

	@Override
	public List<VUser> findAll();

	@Query(value ="SELECT u.* from vUser u "
			+ "where u.isactive = true and u.status=true "
			+ "and u.tenantid=:tenantid and u.username=:username", nativeQuery=true)
	VUser finduserprofile(
			@Param("tenantid")String tenantid,
			@Param("username")String username );

	
	@Query("SELECT u.azureToken FROM VUser u WHERE u.isactive = true and u.id =:id")
	String findAzureToken(@Param("id") Long id);
	
	@Query("SELECT v.azureInfo FROM VUser v WHERE v.id = :userId AND v.isactive = true")
	String findAzureInfoByUserId(@Param("userId") Long userId);
	
	@Query("SELECT u.gcpToken FROM VUser u WHERE u.isactive = true and u.id =:id")
	String findGcpToken(@Param("id") Long id);
	
	@Query("SELECT u.source FROM VUser u WHERE u.isactive = true and u.id =:userId")
	String findSourceById(@Param("userId") Long userId);
	
	@Modifying
	@Query("update VUser set defaultreporttemplate = :defaultreporttemplate WHERE username = :username and isactive=true and status=true ")
	void setDefaultTemplate(@Param("username") String username,@Param("defaultreporttemplate") String defaultreporttemplate);

	@Query(value="SELECT u.defaultreporttemplate FROM VUser u WHERE u.username = :username and u.isactive = true and u.status = true",
			nativeQuery=true)
	String findDefaultReportTemplate(@Param("username") String username);
	
	
}
