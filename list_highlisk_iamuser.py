import boto3


class IamUser:
    def __init__(self, iam, username):
        self.username = username
        self.is_mfa_active = self.__check_is_mfa_active(iam, username)
        self.is_accesskey_active = self.__check_is_accesskey_active(iam, username)

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    def __check_is_mfa_active(self, iam, username):
        """check the user has a active MFA device or not"""
        res = iam.list_mfa_devices(UserName=username)
        if len(res["MFADevices"]) > 0:
            return True
        return False

    def __check_is_accesskey_active(self, iam, username):
        """check the user has a active accesskey or not"""
        res = iam.list_access_keys(UserName=username)
        for accesskey in res["AccessKeyMetadata"]:
            if accesskey["Status"] == "Active":
                return True
        return False


def fetch_userlist_from_entity(iam, policy):
    """return a list of IAM users directly attached to the specified AWS managed policy"""
    users = []
    response = iam.list_entities_for_policy(
        PolicyArn=f"arn:aws:iam::aws:policy/{policy}", MaxItems=1000
    )
    while True:
        res_users = response["PolicyUsers"]
        for res_user in res_users:
            users.append(res_user["UserName"])
        if not response["IsTruncated"]:
            break
        else:
            response = iam.list_entities_for_policy(
                Marker=response["Marker"],
                PolicyArn=f"arn:aws:iam::aws:policy/{policy}",
                MaxItems=1000,
            )
    return users


def fetch_grouplist_from_entity(iam, policy):
    """return a list of IAM groups attached to the specified AWS managed policy"""
    groups = []
    response = iam.list_entities_for_policy(
        PolicyArn=f"arn:aws:iam::aws:policy/{policy}", MaxItems=1000
    )
    while True:
        res_groups = response["PolicyGroups"]
        for res_group in res_groups:
            groups.append(res_group["GroupName"])
        if not response["IsTruncated"]:
            break
        else:
            response = iam.list_entities_for_policy(
                Marker=response["Marker"],
                PolicyArn=f"arn:aws:iam::aws:policy/{policy}",
                MaxItems=1000,
            )
    return groups


def get_userlist_from_group(iam, group):
    """return a list of IAM users associated with the specified user group"""
    users = []
    response = iam.get_group(GroupName=group)
    group_users = response["Users"]
    while True:
        for group_user in group_users:
            users.append(group_user["UserName"])
        if not response["IsTruncated"]:
            break
        else:
            response = iam.get_group(
                Marker=response["Marker"], GroupName=group, MaxItems=1000
            )
    return users


def get_users(iam, policy):
    """return a list of IAM users attached to the specified AWS managed policy"""
    userlist = fetch_userlist_from_entity(iam, policy)
    glouplist = fetch_grouplist_from_entity(iam, policy)

    for group in glouplist:
        userlist.extend(get_userlist_from_group(iam, group))

    return userlist


def get_iamuser_set(iam, policy_list):
    userlist = []
    for policy in policy_list:
        userlist.extend(get_users(iam, policy))
    return set(userlist)


def extract_warning_users(iam, userset):
    for username in userset:
        user = IamUser(iam, username)
        if user.is_accesskey_active and not user.is_mfa_active:
            print(user)


def main():
    iam = boto3.Session().client("iam")
    target_policys = ["AdministratorAccess", "IAMFullAccess", "PoweruserAccess"]

    userset = get_iamuser_set(iam, target_policys)
    extract_warning_users(iam, userset)


if __name__ == "__main__":
    main()
