from pysearpc import searpc_func, NamedPipeClient

class CcnetThreadedRpcClient(NamedPipeClient):

    def __init__(self, socket_path):
        NamedPipeClient.__init__(self, socket_path, "ccnet-threaded-rpcserver")

    @searpc_func("int", ["string", "string", "int", "int"])
    def add_emailuser(self, email, passwd, is_staff, is_active):
        pass
    
    @searpc_func("int", ["string", "string"])
    def remove_emailuser(self, source, email):
        pass
    
    @searpc_func("int", ["string", "string"])
    def validate_emailuser(self, email, passwd):
        pass

    @searpc_func("object", ["string"])
    def get_emailuser(self, email):
        pass

    @searpc_func("object", ["string"])
    def get_emailuser_with_import(self, email):
        pass

    @searpc_func("object", ["int"])
    def get_emailuser_by_id(self, user_id):
        pass

    @searpc_func("objlist", ["string", "int", "int", "string"])
    def get_emailusers(self, source, start, limit, status):
        pass

    @searpc_func("objlist", ["string", "string", "int", "int"])
    def search_emailusers(self, source, email_patt, start, limit):
        pass

    @searpc_func("objlist", ["string", "int", "int"])
    def search_ldapusers(self, keyword, start, limit):
        pass
    
    @searpc_func("int64", ["string"])
    def count_emailusers(self, source):
        pass

    @searpc_func("int64", ["string"])
    def count_inactive_emailusers(self, source):
        pass

    @searpc_func("objlist", ["string"])
    def filter_emailusers_by_emails(self):
        pass
    
    @searpc_func("int", ["string", "int", "string", "int", "int"])
    def update_emailuser(self, source, user_id, password, is_staff, is_active):
        pass

    @searpc_func("int", ["string", "string"])
    def update_role_emailuser(self, email, role):
        pass

    @searpc_func("objlist", [])
    def get_superusers(self):
        pass

    @searpc_func("int", ["string", "string"])
    def add_binding(self, email, peer_id):
        pass
    
    @searpc_func("string", ["string"])
    def get_binding_email(self, peer_id):
        pass
    
    @searpc_func("string", ["string"])
    def get_binding_peerids(self, email):
        pass

    @searpc_func("int", ["string"])
    def remove_binding(self, email):
        pass

    @searpc_func("int", ["string", "string"])
    def remove_one_binding(self, email, peer_id):
        pass
    
    @searpc_func("objlist", ["string"])
    def get_peers_by_email(self, email):
        pass

    @searpc_func("int", ["string", "string", "string", "int"])
    def create_group(self, group_name, user_name, gtype, parent_group_id):
        pass

    @searpc_func("int", ["int", "string", "string", "int"])
    def create_org_group(self, org_id, group_name, user_name, parent_group_id):
        pass
    
    @searpc_func("int", ["int"])
    def remove_group(self, group_id):
        pass

    @searpc_func("int", ["int", "string", "string"])
    def group_add_member(self, group_id, user_name, member_name):
        pass
    
    @searpc_func("int", ["int", "string", "string"])
    def group_remove_member(self, group_id, user_name, member_name):
        pass

    @searpc_func("int", ["int", "string"])
    def group_set_admin(self, group_id, member_name):
        pass

    @searpc_func("int", ["int", "string"])
    def group_unset_admin(self, group_id, member_name):
        pass

    @searpc_func("int", ["int", "string"])
    def set_group_name(self, group_id, group_name):
        pass
    
    @searpc_func("int", ["int", "string"])
    def quit_group(self, group_id, user_name):
        pass

    @searpc_func("objlist", ["string", "int"])
    def get_groups(self, user_name, return_ancestors):
        pass

    @searpc_func("objlist", [])
    def list_all_departments(self):
        pass

    @searpc_func("objlist", ["int", "int", "string"])
    def get_all_groups(self, start, limit, source):
        pass

    @searpc_func("objlist", ["int"])
    def get_ancestor_groups(self, group_id):
        pass

    @searpc_func("objlist", ["int"])
    def get_top_groups(self, including_org):
        pass
    
    @searpc_func("objlist", ["int"])
    def get_child_groups(self, group_id):
        pass

    @searpc_func("objlist", ["int"])
    def get_descendants_groups(self, group_id):
        pass

    @searpc_func("object", ["int"])
    def get_group(self, group_id):
        pass

    @searpc_func("objlist", ["int"])
    def get_group_members(self, group_id):
        pass

    @searpc_func("objlist", ["int", "string"])
    def get_members_with_prefix(self, group_id, prefix):
        pass

    @searpc_func("int", ["int", "string", "int"])
    def check_group_staff(self, group_id, username, in_structure):
        pass

    @searpc_func("int", ["string"])
    def remove_group_user(self, username):
        pass
    
    @searpc_func("int", ["int", "string", "int"])
    def is_group_user(self, group_id, user, in_structure):
        pass

    @searpc_func("int", ["int", "string"])
    def set_group_creator(self, group_id, user_name):
        pass

    @searpc_func("objlist", ["string", "int", "int"])
    def search_groups(self, group_patt, start, limit):
        pass

    @searpc_func("int", ["string", "string", "string"])
    def create_org(self, org_name, url_prefix, creator):
        pass

    @searpc_func("int", ["int"])
    def remove_org(self, org_id):
        pass
    
    @searpc_func("objlist", ["int", "int"])
    def get_all_orgs(self, start, limit):
        pass

    @searpc_func("int64", [])
    def count_orgs(self):
        pass

    @searpc_func("object", ["string"])
    def get_org_by_url_prefix(self, url_prefix):
        pass

    @searpc_func("object", ["string"])
    def get_org_by_id(self, org_id):
        pass
    
    @searpc_func("int", ["int", "string", "int"])
    def add_org_user(self, org_id, email, is_staff):
        pass

    @searpc_func("int", ["int", "string"])
    def remove_org_user(self, org_id, email):
        pass
    
    @searpc_func("objlist", ["string"])
    def get_orgs_by_user(self, email):
        pass
    
    @searpc_func("objlist", ["string", "int", "int"])
    def get_org_emailusers(self, url_prefix, start, limit):
        pass

    @searpc_func("int", ["int", "int"])
    def add_org_group(self, org_id, group_id):
        pass

    @searpc_func("int", ["int", "int"])
    def remove_org_group(self, org_id, group_id):
        pass

    @searpc_func("int", ["int"])
    def is_org_group(self, group_id):
        pass

    @searpc_func("int", ["int"])
    def get_org_id_by_group(self, group_id):
        pass
    
    @searpc_func("objlist", ["int", "int", "int"])
    def get_org_groups(self, org_id, start, limit):
        pass
    
    @searpc_func("objlist", ["string", "int"])
    def get_org_groups_by_user (self, user, org_id):
        pass

    @searpc_func("objlist", ["int"])
    def get_org_top_groups(self, org_id):
        pass

    @searpc_func("int", ["int", "string"])
    def org_user_exists(self, org_id, email):
        pass

    @searpc_func("int", ["int", "string"])
    def is_org_staff(self, org_id, user):
        pass

    @searpc_func("int", ["int", "string"])
    def set_org_staff(self, org_id, user):
        pass

    @searpc_func("int", ["int", "string"])
    def unset_org_staff(self, org_id, user):
        pass

    @searpc_func("int", ["int", "string"])
    def set_org_name(self, org_id, org_name):
        pass
    
    @searpc_func("int", ["string", "string"])
    def set_reference_id(self, primary_id, reference_id):
        pass

    @searpc_func("string", ["string"])
    def get_primary_id(self, email):
        pass

    @searpc_func("objlist", ["string"])
    def get_groups_members(self, group_ids):
        pass

    @searpc_func("objlist", ["string", "string"])
    def get_emailusers_in_list(self, source, user_list):
        pass
