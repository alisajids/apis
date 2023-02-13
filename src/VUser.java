package com.example.common.db.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import org.apache.commons.lang3.StringUtils;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import javax.xml.bind.annotation.XmlTransient;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;

@Entity
@Table(name = "vuser")
@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
@NamedQuery(name = "VUser.findAll", query = "SELECT u FROM VUser u")
@NamedQuery(name = "VUser.findByUserDetails", query = "SELECT u FROM VUser u where u.id=:userid and u.isactive = true")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VUser extends CommonAudit implements Serializable {

	public static final boolean ENABLED = true;
	public static final boolean DISABLED = false;
	
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "id")
    @EqualsAndHashCode.Include
    private Long id;
    
    @Basic(optional = false)
    @Column(name = "firstname")
    private String firstname;
    
    @Basic(optional = false)
    @Column(name = "lastname")
    private String lastname;
    
    @Column(name = "middlename")
    private String middlename;
    
    @Basic(optional = false)
    @Column(name = "username")
    private String username;
    
    @Basic(optional = false)
    @Column(name = "email")
    private String email;
    
    @Basic(optional = false)
    @Column(name = "isactive")
    private boolean isactive;
    
    @Basic(optional = false)    
    @Column(name = "status")
    private boolean status = true;
    
    @Column(name = "islocked")
    private boolean islocked;
    
    @Column(name = "lastpasswordchangedate")
    @Temporal(TemporalType.TIMESTAMP)
    private Date lastpasswordchangedate;
    
    @Column(name = "tenantid")
    @Type(type = "pg-uuid")
    private UUID tenantid;
    
    @Column(name = "phonenumber")
    private String phoneNumber;
    
    @Getter
    @Setter
    @Column(name = "xskey")
    private String xskey;
    
    @Getter
    @Setter
    @Column(name = "xssecret")
    private String xssecret;
    
    @Getter
    @Setter
    @Column(name = "rid")
    private String rid;

	@Getter
	@Setter
	@Column(name = "xstream_info")
	private String xstreamInfo;

	@Getter
	@Setter
	@Column(name = "gcp_info")
	private String gcpInfo;

    @Getter
    @Setter
    @Column(name = "gcp_token")
    private String gcpToken;

	@Getter
	@Setter
	@Column(name = "azure_info")
	private String azureInfo;

	@Getter
	@Setter
	@Column(name = "azure_token")
	private String azureToken;

    @Getter
    @Setter
    @Column(name = "source")
    private String source;
	
    @Getter
    @Setter
    @Column(name = "regitokenexpirationdate")
    private Timestamp regitokenexpirationdate;
   
    @Getter
    @Setter
    @Column(name = "registrationtoken")
    private String registrationtoken;
    
    @Getter
    @Setter
    @Column(name = "registrationstatus")
    private Boolean registrationstatus;
     
    @Column(name = "authenticationtype_id")
    private Long authenticationtypeId;

	@Column(name = "lastloginfailuretime")
    private Timestamp lastloginfailuretime;
    
    @Column(name = "loginfailurecount")
    private Integer loginfailurecount;
	
    @Column(name = "loginfailureip")
    private String loginfailureip;

    @Getter
    @Setter
    @Column(name = "mfa_enable")
    private boolean  mfaEenable;

    @Getter
    @Setter
    @Column(name = "mfa_code")
    private String  mfaCode;
    
    @Getter
    @Setter
    @Column(name = "forgotpwdtoken")
    private String  forgotpwdtoken;
    
    @Getter
    @Setter
    @Column(name = "forgotpwdtokenexpirationdate")
    private Timestamp  forgotpwdtokenexpirationdate;
    
    @Getter
    @Setter
    @Column(name = "forgotpwdstatus")
    private Boolean  forgotpwdstatus;

    @Setter
    @Column(name = "accountlockedtime")
    private Timestamp accountlockedtime;
    
    @Getter
    @Setter
    @Column(name = "ping_token")
    private String  pingtoken;

    @Getter
    @Setter
    @Column(name = "defaultreporttemplate")
    private String defaultReportTemplate;
    
    //@JoinColumn(name = "tenantid", referencedColumnName = "tenantid", insertable=false, updatable=false)
    //@ManyToOne
    @Transient
    private Tenant tenant;

    
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "userId")
    private Collection<Usercredential> usercredentialsCollection;
    
    @Getter @Setter
    @OneToMany(mappedBy = "userId")
    private Collection<Usertofeaturepermission> usertofeaturepermissionCollection;
    
    //Constructors
    public VUser() {
    }
    public VUser(Long id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "VUser[ id=" + id + " ]";
    }

    //Getters-Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getMiddlename() {
        return middlename;
    }

    public void setMiddlename(String middlename) {
        this.middlename = middlename;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
    	if (StringUtils.isNotBlank(username))
    		username = username.trim();
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean getIsactive() {
        return isactive;
    }

    public void setIsactive(boolean isactive) {
        this.isactive = isactive;
    }

    public boolean getIslocked() {
        return islocked;
    }

    public void setIslocked(boolean islocked) {
        this.islocked = islocked;
    }

    public boolean isStatus() {
		return status;
	}

	public void setStatus(boolean status) {
		this.status = status;
	}
	
    public Date getLastpasswordchangedate() {
    	if (lastpasswordchangedate == null) { 
    		Calendar myCal = Calendar.getInstance();
    		myCal.set(Calendar.YEAR, 2017);
    		myCal.set(Calendar.MONTH, 00);
    		myCal.set(Calendar.DAY_OF_MONTH, 01);
    		lastpasswordchangedate = myCal.getTime(); //Default value for a Date type.
    	}
        return lastpasswordchangedate;
    }

    public void setLastpasswordchangedate(Date lastpasswordchangedate) {
        this.lastpasswordchangedate = lastpasswordchangedate;
    }

    public UUID getTenantid() {
        return tenantid;
    }

    public void setTenantid(UUID tenantid) {
        this.tenantid = tenantid;
    }
    
    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }
    
    public Long getAuthenticationtypeId() {
        return authenticationtypeId;
    }

    public void setAuthenticationtypeId(Long authenticationtypeId) {
        this.authenticationtypeId = authenticationtypeId;
    }

    @XmlTransient
    public Collection<Usercredential> getUsercredentialsCollection() {
        return usercredentialsCollection;
    }

    public void setUsercredentialsCollection(Collection<Usercredential> usercredentialsCollection) {
        this.usercredentialsCollection = usercredentialsCollection;
    }

	public Timestamp getLastloginfailuretime() {
		return lastloginfailuretime;
	}

	public void setLastloginfailuretime(Timestamp lastloginfailuretime) {
		this.lastloginfailuretime = lastloginfailuretime;
	}

	public Integer getLoginfailurecount() {
		return loginfailurecount;
	}

	public void setLoginfailurecount(Integer loginfailurecount) {
		this.loginfailurecount = loginfailurecount;
	}

	public String getLoginfailureip() {
		return loginfailureip;
	}

	public void setLoginfailureip(String loginfailureip) {
		this.loginfailureip = loginfailureip;
	}

	public Timestamp getAccountlockedtime() {
		return accountlockedtime;
	}

    public String getPhoneNumber() {
		return phoneNumber;
	}
    
	public void setPhoneNumber(String phoneNumber) {
		this.phoneNumber = phoneNumber;
	}   
}
