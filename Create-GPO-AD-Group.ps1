UNOFFICIAL

##############################################
# Powershell functions to create AD Objects. #
##############################################
#
# Version 1.0
# - Initial Release
# Version 1.1 - 20180531
# - Fixed up RDP group to be "Allow Log on through remote desktop services" rather than adding them to BUILTIN\Remote Desktop Users
# - Added Notes for Groups as per feedback from ***
# - Added replication waits 
# - Added new RBAC
# - Added ad server
# Version 1.2 - 20180608
# - Fixed up Global group nesting error which doesn't appear in the logs.
#
# Functions you should be calling
#  RBACTemplateCreationWindows($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $rbacname, $secfilter, $svcgroup)
#  RBACTemplateCreationWindowsSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $rbacname, $secfilter, $svcgroup, $roleadmin, $rolappdev, $reswinadmin)
#  RBACTemplateCreationUnix($environment, $appid, $appname, $domain, $ou, $dc, $chgnum)
#  RBACTemplateCreationLinuxSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $roleadmin, $rolappdev, $reslinuxadmin, $reslinuxappmgr, $reslinuxaccess)
#  RBACTemplateCreationSolarisSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $roleadmin, $rolappdev, $ressoladmin, $ressolappdev)
#  RBACTemplateCreationSQL($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $dbsecfilter)
#  RBACTemplateCreationSQLClusSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $dbsecfilter, $roleadmin, $rolappdev, $ressqlclusadmin, $resdsqldbo)
#  RBACTemplateCreationSQLStandaloneSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $dbsecfilter, $roleadmin, $rolappdev, $ressqlstandadmin, $resdsqldbo)
#
# 


#Global Test flag, nothing will be created (queries will still go through)
$testonly = $false

#Constants and settings
$noaction = 0
$ok = 0
$bad = 1
$resourceOU = "OU=Resource,OU=Groups,OU=CP"
$roleOU = "OU=Roles - Applications,OU=Groups,OU=CP"
$GPOfilterOU = "OU=Group Policy,OU=Groups,OU=CP"
$currenttime = Get-Date -f "yyyyMMdd_HHmmss"
$logprefix = "Script_output_"
$logdir = $null
$replicationnum = 5
$replicationsec = 5
$global:adserver = $null # if you do not set this in the script, PDC will be used (it's more reliable this way)
$global:logpath = ""

function Log($string)
{
Write-Host $string
try {
  if ($logdir -ne $null) {
   $validdir = Test-Path -Path $logdir
   if ($d -eq $false) {
     New-Item -ItemType directory -Path $logdir
   }
   if ($logprefix -notmatch "^[A-Za-z\-0-9]*$") {
     #Write-Host "WARN: $logprefix doesn't conform to CHT-0000000-DXE naming standards, defaulting to Script_output_"
       $logprefix = "Script_output_"
   }
   $global:logpath = $logdir +"\\" + $logprefix + $currenttime + ".txt"
   $string | Out-File $global:logpath -Append
  }
}
catch {
  Write-Host "WARN: Cannot write to $logdir"
}
}

##################################################
#### PRIVATE FUNCTIONS BELOW - IGNORE PLEASE #####
##################################################

# Tests if you have AD Snapins...
function Test-ADLDS()
{
Get-Module ActiveDirectory | Out-Null
if (Get-Command Get-ADGroup -errorAction SilentlyContinue)
{
  if ($global:adserver -eq $null) {
   $obj = Get-ADDomain;
   $global:adserver = $obj.PDCEmulator
   Log "INFO: AD Domain Controller: $global:adserver"
  }
  return ""
}
return "ERROR: No Active Directory LDS Powershell snapin, please run this on the jumphost or have it installed =)"
}

function PrivateCreateOU ($name, $parent, $description)
{
$ouDN = "OU=$name,$parent"
try {
  Get-ADOrganizationalUnit -Identity $ouDN -Server $global:adserver | Out-Null
  Log "INFO: $ouDN already exists"
  return $noaction
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
  if ($testonly -eq $false) {
   New-ADOrganizationalUnit -Name $name -Path $parent -Description $description -Server $global:adserver | Out-Null
   Log "INFO: $ouDN created."
   $idx = 0;
   while ($idx -lt $replicationnum) {
    Log "INFO: Wait for replication... $idx"
    try {
     if (Get-ADOrganizationalUnit -LDAPFilter "(name=$name)" -SearchBase "$parent" -Server $global:adserver) {
         break;
       }
       }
       catch {
       }
    sleep $replicationsec
       $idx = $idx + 1
   }
  }
  else {
   Log "INFO: TEST-ONLY - New-ADOrganizationalUnit $name $parent $server"
  }
  return $ok
}
return $bad
}

function PrivateCreateGroup($group, $parentou, $dc, $description, $notes)
{
$parent = "$parentou,$dc"
$ouDN = "CN=$group,$parent"
$GroupScope = "Global"
if ($group -match "-D-") {
  $GroupScope = "DomainLocal"
} 
 try {
  Get-ADGroup $group -Server $global:adserver | Out-Null
  Log "INFO: $group already exists"
  return $noaction
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
  if ($testonly -eq $false) {
   New-ADGroup -Name $group -Path $parent -GroupScope $GroupScope -Description $description -Server $global:adserver -OtherAttributes @{info="$notes"} | Out-Null
   Log "INFO: $ouDN created."
   $idx = 0;
   while ($idx -lt $replicationnum) {
    Log "INFO: Wait for replication... $idx"
    try {
     if (Get-ADGroup -LDAPFilter "(SamAccountName=$group)" -SearchBase $dc -Server $global:adserver) {
         break;
       }
       }
       catch {
       }
    sleep $replicationsec
       $idx = $idx + 1
   }
  }
  else {
   Log "INFO: TEST-ONLY - New-ADGroup $name $parent $GroupScope $server $description" 
  }
  return $ok
}
return $bad
}

function PrivateCreateRBACGPO($domain, $rbacname, $comment, $secfilter, $svcgroup, $localadmingroup, $rdpgroup, $pwrusrgroup, $rbactemplate, $ou, $dc)
{
if (($rbacname -eq $null) -or ($rbacname -eq "") -or ($secfilter -eq $null) -or ($secfilter -eq "")) {
   Log "WARN: RBAC Name: $rbacname OR Sec Filter: $secfilter is empty, no GPO will be created"
   return $noaction
}
$tempgpo = Get-GPO -Name $rbactemplate -ErrorAction SilentlyContinue
if ($tempgpo -eq $null) {
   Log "ERROR: Template GPO $rbactemplate not found in domain"
   return $bad
} 
 $TMPDIR = (Get-Item -Path ".\").FullName
$gpo = Get-GPO -Name $rbacname -ErrorAction SilentlyContinue
if ($gpo -eq $null) {
  if ($testonly -eq $true) {
   Log "Copy-GPO -SourceName $rbactemplate -TargetName $rbacname"
   Log "Backup-GPO -name $rbacname"
   Log "Import-gpo -backupgponame $rbacname -TargetName $rbacname"
   Log "Set-GPPermission -Name $rbacname -TargetName $secfilter -TargetType Group -PermissionLevel GpoApply "
   return $ok
  }
  $WORKINGTMP = "workingtemp_$currenttime"
  New-Item -ItemType directory -Path "$TMPDIR\$WORKINGTMP\"  | Out-Null
  $newgpo = Copy-GPO -SourceName $rbactemplate -TargetName $rbacname
  Log "INFO: Template GPO $rbactemplate copied. Wait for replication..."
  sleep $replicationsec
  
  $newgpo.Description  = $comment
  
  $backupgpo = Backup-GPO -name $rbacname -Path "$TMPDIR\$WORKINGTMP\"
  $idpath = "{" + $backupgpo.id + "}"
  $file = $TMPDIR + "\" + $WORKINGTMP + "\" + $idpath + "\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
  
  (Get-Content $file) -replace "^(Revision=).*$", '${1}2' `
                      -replace "^(SeDenyInteractiveLogonRight.*)$"      , "`${1},$domain\$svcgroup" `
                                    -replace "^(SeDenyRemoteInteractiveLogonRight.*)$", "`${1},$domain\$svcgroup" `
                                    -replace "^(SeBatchLogonRight.*)$"                , "`${1},$domain\$svcgroup" `
                                    -replace "^(SeServiceLogonRight.*)$"              , "`${1},$domain\$svcgroup" | Set-Content $file

  # only apply if local admin group has been put in
  if (($localadmingroup -ne $null ) -and ($localadmingroup -ne "")) {
    (Get-Content $file) -replace "^(\*S-1-5-32-544__Members =.*)$"        , "`${1},$domain\$localadmingroup" | Set-Content $file
    (Get-Content $file) -replace "^(\*S-1-5-32-544__Members =)$"        , "`${1} $domain\$localadmingroup" | Set-Content $file
  }
  
  # only apply if rdp group has been put in
  if (($rdpgroup -ne $null ) -and ($rdpgroup -ne "")) {
    (Get-Content $file) -replace "^(SeRemoteInteractiveLogonRight.*)$"        , "`${1},$domain\$rdpgroup" | Set-Content $file
       # RDP Group controlled by "Allow Log on through terminal services" GPO rather than the local group.
    #(Get-Content $file) -replace "^(\*S-1-5-32-555__Members = .*)$"        , "`${1},$domain\$rdpgroup" | Set-Content $file
    #(Get-Content $file) -replace "^(\*S-1-5-32-555__Members =)$"        , "`${1} $domain\$rdpgroup" | Set-Content $file
  }
  
  # only apply if power user group has been put in
  if (($pwrusrgroup -ne $null ) -and ($pwrusrgroup -ne "")) {
    (Get-Content $file) -replace "^(\*S-1-5-32-547__Members = .*)$"        , "`${1},$domain\$pwrusrgroup" | Set-Content $file
    (Get-Content $file) -replace "^(\*S-1-5-32-547__Members =)$"        , "`${1} $domain\$pwrusrgroup" | Set-Content $file
  }
  
  # NOTE: 
  # to add additional filters
  # - if it's something which is applied to all machines, I would recommend putting it in the RBACTemplate GPO instead.
  # - if it's something app specific, ensure the relevant RES are created and you will need to add the res group
  # - eg/ DOMAIN\RES-blah-blah
  # To get a snippet of the above file
  # Run
  #  Backup-GPO -name "RBACTemplate" -Path "C:\temp\rbactemp"
  # then find the GptTmpl.ini file within one of the subfolders and have a look at the syntax.
  # The S-1-5-32-XXX__Members notation is from the Microsoft Common SID for accounts website, look it up.

  Import-gpo -backupgponame $rbacname -TargetName $rbacname -Path "$TMPDIR\$WORKINGTMP\"  | Out-Null
  Log "INFO: GPO $rbacname Created Successfully! Wait for replication..."
  sleep $replicationsec
  
  Set-GPPermission -Name $rbacname -TargetName $secfilter -TargetType Group -PermissionLevel GpoApply  | Out-Null
  
  # Add authenticated users as GpoRead
  Set-GPPermission -Name $rbacname -TargetName "Authenticated Users" -PermissionLevel GpoRead -TargetType Group -Replace | Out-Null
  
  Log "INFO: GPO $secfilter Security Filter Applied Successfully! Wait for replication..."
  sleep $replicationsec

  Remove-Item "$TMPDIR\$WORKINGTMP\" -Force -Recurse  | Out-Null
  
  $fullou = "$ou,$dc"
  
  Get-ADOrganizationalUnit -Identity $fullou -Server $global:adserver | Out-Null
  New-GPLink -Name $rbacname -Target $fullou -LinkEnabled Yes | Out-Null
  Log "INFO: GPO $rbacname linked to $fullou. Wait for replication..."
  sleep $replicationsec
  
  return $ok
}
else {
  Log "INFO: GPO $rbacname already exists."
} 
 return $noaction
}

##################################################
#### PRIVATE FUNCTIONS ABOVE - IGNORE PLEASE #####
##################################################

# Creates the OU and the sub OUs
# Eg/ CreateOU "ou=APP-123name,ou=applications,ou=cp" "dc=something,dc=unclassified,dc=something,dc=au" "Change Number"
#
function CreateOU ($ou, $dc, $description)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
} 
 if (($ou -eq $null) -or ($ou -eq "")) {
  Log "INFO: No OU name passed in, no action performed"
  return $noaction
}
$splitou = $ou.split(",")
$currentOU = $dc
$i = $splitou.length
$ret = $ok
while ($i -gt 0) {
  $i = $i - 1;
  $nextou = $splitou[$i]
  $begin = $nextou.split("=")
  if ($begin.length -gt 1) {
   $name = $begin[1]
   $r = PrivateCreateOU $name $currentOU $description
   $ret = $ret + $r
  }
  else {
   Log "WARN: $nextou is not an OU"
  }
  $currentOu = $splitou[$i] + "," + $currentOu
}
return $ret
}

# Creates a group (use the helper functions below)
function CreateGroup($group, $parentou, $dc, $description, $notes)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
if (($group -eq $null) -or ($group -eq "")) {
  Log "INFO: No group name passed in, no action performed for $description"
  return $noaction
}
$name = $group
if ($group.startswith("CN=","CurrentCultureIgnoreCase"))
{
  $name = $group.substring(3)
}
$ret = CreateOU $parentou $dc "" $server $credential
$ret2 = PrivateCreateGroup $group $parentou $dc $description $notes
return $ret + $ret2
}


# Creates a group in the CP Resource Groups area.
# server and credential optional
# 
# CreateResourceGroup "RES-D-ABC-Resource" "dc=something,dc=unclassified,dc=something,dc=au" "Whatever description to satisfy ****, maybe the change number"
function CreateResourceGroup ($group, $dc, $description, $notes, $parentou = $resourceOU)
{
return CreateGroup $group $parentou $dc $description $notes
}

# Creates a group in the CP Role Groups area.
# 
# CreateRoleGroup "ROL-G-ABC-Resource" "dc=something,dc=unclassified,dc=something,dc=au" "Whatever description to satisfy ****, maybe the change number"
function CreateRoleGroup ($group, $dc, $description, $notes, $parentou = $roleOU)
{
return CreateGroup $group $parentou $dc $description $notes
}

# Creates a GPO Filter group in the CP Role Groups area.
# 
# CreateGPOFilterGroup "O-C-ABC-Resource-01f" "dc=something,dc=unclassified,dc=something,dc=au" "Whatever description to satisfy ****, maybe the change number"
function CreateGPOFilterGroup ($group, $dc, $description, $notes, $parentou = $GPOfilterOU)
{
return CreateGroup $group $parentou $dc $description $notes
}

# Nest 2 groups.
# 
# NestGroup "RES-D-ABC-Resource" "ROL-G-ABC-Resource"
function NestGroups($parent, $name) 
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
try {
   if ($parent -eq "") {
     Log "ERROR: $parent group not found, no nesting performed for $name"
       return $bad
   }
   if ($name -eq "") {
     Log "ERROR: $name group not found, no nesting performed for $parent"
       return $bad
   }
   $high = Get-ADGroup -Filter {SamAccountName -eq $parent} -Server $global:adserver -ErrorAction SilentlyContinue
   $sub = Get-ADGroup -Filter {SamAccountName -eq $name} -Server $global:adserver -ErrorAction SilentlyContinue
   if ($high -eq $null) {
     Log "ERROR: $parent group not found, no nesting performed for $name"
       return $bad
   }
   if ($sub -eq $null) {
     Log "ERROR: $name group not found, no nesting performed for $parent"
       return $bad
   }
  
   # objects are all good
   $members = Get-ADGroupMember $high -Server $global:adserver  | Select -ExpandProperty Name
   if ($members -notcontains $name) {
    if ($testonly -eq $false) {
       try {
      Add-ADGroupMember $high $sub -Server $global:adserver 
         Log "INFO: $name nested in $parent"
       }
       catch {
         $message = $_.Exception.Message
         Log "ERROR: Error nesting $name in $parent - $message"
         return $bad
       }
       }
       else {
       Log "INFO: TEST-ONLY - Add-ADGroupMember $high $sub"
       }
       return $ok
   }
   else {
    Log "INFO: $name already nested in $parent"
   }
  return $noaction
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
  Log "WARN: One of $parent or $name not found - not nesting"
  return $noaction
}
}

# Base Windows RBAC
# returns 0 if it's all good, any other number indicates partial failure or full failure.
function RBACTemplateCreationWindows($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $rbacname, $secfilter, $svcgroup, $reswinadmin = "", $reswinpwr = "", $reswinrdp = "")
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: Environment - $environment"
Log "INFO: PARAM: APP ID - $appid"
Log "INFO: PARAM: APP NAME - $appname"
Log "INFO: PARAM: Domain - $Domain"
Log "INFO: PARAM: OU - $ou"
Log "INFO: PARAM: DC - $dc"
Log "INFO: PARAM: RBACName - $rbacname"
Log "INFO: PARAM: CHG Number - $chgnum"
Log "INFO: PARAM: Sec Filter - $secfilter"
Log "INFO: PARAM: SVC Group - $svcgroup"

# For each function
# Step 1 Create OU
$ret = CreateOU $ou $dc $chgnum
$errnum = $ret;
# Step 2 Create missing groups (as required)
$ret = CreateGPOFilterGroup $secfilter $dc "GPO filtering group for $appid $appname $environment Servers" "Only $appid $appname $environment Computer Objects should be added as member; DO NOT add any User Accounts to this group. $chgnum"
$errnum = $errnum + $ret;

$ret = CreateResourceGroup $svcgroup $dc "Standard service account lockdown applied via GPO to $appid $appname $domain Servers" "DO NOT add users directly to resource group; service account can be added directly. Only $appname application related service accounts should be member of this group. $chgnum"
$errnum = $errnum + $ret;

 # Step 3 Create GPO and link GPO
# PrivateCreateRBACGPO($domain, $rbacname, $comment, $secfilter, $svcgroup, $localadmingroup, $rdpgroup, $pwrusrgroup, $rbactemplate = "RBACTemplate")
$ret = PrivateCreateRBACGPO $domain $rbacname $chgnum $secfilter $svcgroup $reswinadmin $reswinpwr $reswinrdp "O-C-RBACTemplate-Security-$environment-01f" $ou $dc
$errnum = $errnum + $ret;
return $errnum
}

# Creates RBAC Template for this app - along with associated groups and what not if it doesn't exist
function RBACTemplateCreationWindowsSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $rbacname, $secfilter, $svcgroup, $roleadmin, $rolappdev, $reswinadmin)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: roleadmin - $roleadmin"
Log "INFO: PARAM: reswinadmin - $reswinadmin"
Log "INFO: PARAM: rolappdev - $rolappdev"

 $errnum = RBACTemplateCreationWindows $environment $appid $appname $domain $ou $dc $chgnum $rbacname $secfilter $svcgroup $reswinadmin

 
 $ret = CreateRoleGroup $roleadmin $dc "$appid $appname $environment Server Administrators Role Group" "DO NOT add users directly to this group. Only $domain priv IDs should be added as member. $chgnum"
$errnum = $errnum + $ret
$ret = CreateRoleGroup $rolappdev $dc "$appid $appname $environment Server Application Developer Role Group" "$domain Priv accounts only.  No changes without the approval of the $appname project manager. $chgnum"
$errnum = $errnum + $ret

 $ret = CreateResourceGroup $reswinadmin $dc "Local Administrators membership of computers under $ou for $appname $environment Servers within GPO filter $secfilter" "Members may include ROL groups, on the approval of ****. Privileged Roles only. $chgnum"
$errnum = $errnum + $ret

 $ret = NestGroups $reswinadmin $roleadmin
$errnum = $errnum + $ret

 return $errnum
}

# Base Unix (Linux/Solaris) RBAC
# returns 0 if it's all good, any other number indicates partial failure or full failure.
function RBACTemplateCreationUnix($environment, $appid, $appname, $domain, $ou, $dc, $chgnum)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: Environment - $environment"
Log "INFO: PARAM: APP ID - $appid"
Log "INFO: PARAM: APP NAME - $appname"
Log "INFO: PARAM: Domain - $Domain"
Log "INFO: PARAM: OU - $ou"
Log "INFO: PARAM: DC - $dc"
Log "INFO: PARAM: CHG Number - $chgnum"

 # OU creation only.
$errnum = CreateOU $ou $dc $chgnum
return $errnum
}

# Linux SIT RBAC
# returns 0 if it's all good, any other number indicates partial failure or full failure.
function RBACTemplateCreationLinuxSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $roleadmin, $rolappdev, $reslinuxadmin, $reslinuxappmgr, $reslinuxaccess)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: roleadmin - $roleadmin"
Log "INFO: PARAM: rolappdev - $rolappdev"
Log "INFO: PARAM: reslinuxadmin - $reslinuxadmin"
Log "INFO: PARAM: reslinuxappmgr - $reslinuxappmgr"
Log "INFO: PARAM: reslinuxaccess - $reslinuxaccess"

 $errnum = RBACTemplateCreationUnix $environment $appid $appname $domain $ou $dc $chgnum

 $ret = CreateRoleGroup $roleadmin $dc "$appid $appname $environment Server Administrators Role Group" "DO NOT add users directly to this group. Only $domain priv IDs should be added as member. $chgnum"
$errnum = $errnum + $ret
$ret = CreateRoleGroup $rolappdev $dc "$appid $appname $environment Server Application Developer Role Group" "$domain Priv accounts only.  No changes without the approval of the $appname project manager. $chgnum"
$errnum = $errnum + $ret

 $ret = CreateResourceGroup $reslinuxadmin $dc "Linux Local full Administrators access on $appid $appname $environment Servers under $ou" "Members may include ROL groups, on the approval of ****. Privileged Roles only. $chgnum"
$errnum = $errnum + $ret
$ret = CreateResourceGroup $reslinuxappmgr $dc "Linux application manager which allows su to application accounts on $appid $appname $environment Servers under $ou" "Members may include ROL groups, on the approval of ****. Privileged Roles only. $chgnum"
$errnum = $errnum + $ret
$ret = CreateResourceGroup $reslinuxaccess $dc "Linux remote server access on $appid $appname $environment Servers under $ou" "Members may include ROL groups, on the approval of ****. Privileged Roles only. $chgnum"
$errnum = $errnum + $ret

 $ret = NestGroups $reslinuxadmin $roleadmin
$errnum = $errnum + $ret
$ret = NestGroups $reslinuxappmgr $roleadmin
$errnum = $errnum + $ret
$ret = NestGroups $reslinuxaccess $roleadmin
$errnum = $errnum + $ret

 return $errnum
}

# Solaris SIT RBAC
# returns 0 if it's all good, any other number indicates partial failure or full failure.
function RBACTemplateCreationSolarisSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $roleadmin, $rolappdev, $ressoladmin, $ressolappdev)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: roleadmin - $roleadmin"
Log "INFO: PARAM: rolappdev - $rolappdev"
Log "INFO: PARAM: ressoladmin - $ressoladmin"
Log "INFO: PARAM: ressolappdev - $ressolappdev"

 $errnum = RBACTemplateCreationUnix $environment $appid $appname $domain $ou $dc $chgnum

 $ret = CreateRoleGroup $roleadmin $dc "$appid $appname $environment Server Administrators Role Group" "DO NOT add users directly to this group. Only $domain priv IDs should be added as member. $chgnum"
$errnum = $errnum + $ret
$ret = CreateRoleGroup $rolappdev $dc "$appid $appname $environment Server Application Developer Role Group" "$domain Priv accounts only.  No changes without the approval of the $appname project manager. $chgnum"
$errnum = $errnum + $ret

 $ret = CreateResourceGroup $ressoladmin $dc "Solaris Administrators access on $appid $appname $environment Servers under $ou" "Members may include ROL groups, on the approval of ****. Privileged Roles only. $chgnum"
$errnum = $errnum + $ret
$ret = CreateResourceGroup $ressolappdev $dc "Solaris application developer access on $appid $appname $environment Servers" "Membership is restricted to $rolappdev only.  No changes without the approval of ROL managers for $rolappdev. $chgnum"
$errnum = $errnum + $ret

 $ret = NestGroups $ressoladmin $roleadmin
$errnum = $errnum + $ret
$ret = NestGroups $ressolappdev $rolappdev
$errnum = $errnum + $ret

 return $errnum
}

# Base SQL (Standalone/Cluster) RBAC
# returns 0 if it's all good, any other number indicates partial failure or full failure.
function RBACTemplateCreationSQL($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $dbsecfilter)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: Environment - $environment"
Log "INFO: PARAM: APP ID - $appid"
Log "INFO: PARAM: APP NAME - $appname"
Log "INFO: PARAM: Domain - $Domain"
Log "INFO: PARAM: OU - $ou"
Log "INFO: PARAM: DC - $dc"
Log "INFO: PARAM: CHG Number - $chgnum"
Log "INFO: PARAM: dbsecfilter - $dbsecfilter"

 $errnum = CreateOU $ou $dc $chgnum

 $ret = CreateGPOFilterGroup $dbsecfilter $dc "GPO filtering group for $appid $appname $environment SQL Database Servers" "Only $appid $appname $environment SQL Server Computer Objects should be added as member; DO NOT add any User Accounts to this group. $chgnum"
$errnum = $errnum + $ret;

 return $errnum
}

# SQL Cluster SIT RBAC
# returns 0 if it's all good, any other number indicates partial failure or full failure.
function RBACTemplateCreationSQLClusSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $dbsecfilter, $roleadmin, $rolappdev, $ressqlclusadmin, $resdsqldbo)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: roleadmin - $roleadmin"
Log "INFO: PARAM: rolappdev - $rolappdev"
Log "INFO: PARAM: ressqlclusadmin - $ressqlclusadmin"
Log "INFO: PARAM: resdsqldbo - $resdsqldbo"

 $errnum = RBACTemplateCreationSQL $environment $appid $appname $domain $ou $dc $chgnum $dbsecfilter

 $ret = CreateRoleGroup $roleadmin $dc "$appid $appname $environment Server Administrators Role Group" "DO NOT add users directly to this group. Only $domain priv IDs should be added as member. $chgnum"
$errnum = $errnum + $ret
$ret = CreateRoleGroup $rolappdev $dc "$appid $appname $environment Server Application Developer Role Group" "$domain Priv accounts only.  No changes without the approval of the $appname project manager. $chgnum"
$errnum = $errnum + $ret

 $ret = CreateResourceGroup $ressqlclusadmin $dc "SQL Server Cluster database administrator access for $appid $appname $environment" "Membership is restricted to $rolappdev only.  No changes without the approval of ROL managers for $rolappdev. $chgnum"
$errnum = $errnum + $ret
$ret = CreateResourceGroup $resdsqldbo $dc "SQL Server database owner access for $appid $appname $environment" "Membership is restricted to $rolappdev only.  No changes without the approval of ROL managers for $rolappdev. $chgnum"
$errnum = $errnum + $ret

 $ret = NestGroups $ressqlclusadmin $rolappdev
$errnum = $errnum + $ret
$ret = NestGroups $resdsqldbo $rolappdev
$errnum = $errnum + $ret

 return $errnum
}

# SQL Standalone SIT RBAC
# returns 0 if it's all good, any other number indicates partial failure or full failure.
function RBACTemplateCreationSQLStandaloneSIT($environment, $appid, $appname, $domain, $ou, $dc, $chgnum, $dbsecfilter, $roleadmin, $rolappdev, $ressqlstandadmin, $resdsqldbo)
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return $bad
}
Log "INFO: PARAM: roleadmin - $roleadmin"
Log "INFO: PARAM: rolappdev - $rolappdev"
Log "INFO: PARAM: ressqlstandadmin - $ressqlstandadmin"
Log "INFO: PARAM: resdsqldbo - $resdsqldbo"

 $errnum = RBACTemplateCreationSQL $environment $appid $appname $domain $ou $dc $chgnum $dbsecfilter

 $ret = CreateRoleGroup $roleadmin $dc "$appid $appname $environment Server Administrators Role Group" "DO NOT add users directly to this group. Only $domain priv IDs should be added as member. $chgnum"
$errnum = $errnum + $ret
$ret = CreateRoleGroup $rolappdev $dc "$appid $appname $environment Server Application Developer Role Group" "$domain Priv accounts only.  No changes without the approval of the $appname project manager. $chgnum"
$errnum = $errnum + $ret

 $ret = CreateResourceGroup $ressqlstandadmin $dc "SQL Server Standalone database administrator access for $appid $appname $environment" "Membership is restricted to $rolappdev only.  No changes without the approval of ROL managers for $rolappdev. $chgnum"
$errnum = $errnum + $ret
$ret = CreateResourceGroup $resdsqldbo $dc "SQL Server database owner access for $appid $appname $environment" "Membership is restricted to $rolappdev only.  No changes without the approval of ROL managers for $rolappdev. $chgnum"
$errnum = $errnum + $ret

 $ret = NestGroups $ressqlstandadmin $rolappdev
$errnum = $errnum + $ret
$ret = NestGroups $resdsqldbo $rolappdev
$errnum = $errnum + $ret

 return $errnum
}


# Applies RBAC to a computer object
# server and credential optional
#
# ApplyRBACToComputer "sieud01abc0000" "O-C-ABC-Resource-01f" "ou=APP-123name,ou=applications,ou=cp" "dc=something,dc=unclassified,dc=something,dc=au"
function ApplyRBACToComputer($compname, $secgroup, $appOU, $dc) 
{
$r = Test-ADLDS
if ($r -ne "") {
  Log "ERROR: $r"
  return
}
$ouDN = "$appOU,$dc"
try {
  if ($testonly -eq $false) {
    Get-ADOrganizationalUnit -Identity $ouDN | Out-Null
    $group = Get-ADGroup $secgroup -Server $global:adserver
    $comp = Get-ADComputer $compname -Server $global:adserver
       
    # objects are all good
    Add-ADGroupMember $group $comp -Server $global:adserver
    Log "INFO: Nested $compname in $secgroup"
    Move-ADObject -Identity $comp -TargetPath $ouDN -Server $global:adserver
    Log "INFO: Moved $compname to $ouDN"
    Log "INFO: Attempt to Invoke gpupdate on $compname with at least 30min delay (No errors printed if machine offline)"
       Invoke-GPUpdate -Computer $compname -Target "Computer" -RandomDelayInMinutes 30 -ErrorAction SilentlyContinue
  }
  else {
   Log "INFO: TEST-ONLY - Add-ADGroupMember $secgroup $compname"
   Log "INFO: TEST-ONLY - Move-ADObject -Identity $comp -TargetPath $ouDN"
  }
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
  Log "WARN: One of $ouDN or $secgroup or $compname not found - not applying RBAC"
}
}
