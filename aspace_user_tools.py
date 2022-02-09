#/usr/bin/python3

from collections import defaultdict
import json
import pprint
import random
import string

import requests

'''
Update data
'''

def remove_all_permissions(api_url, sesh, user):
  user_json = sesh.get(f"{api_url}{user}").json()
  user_json['permissions'] = {}
  return user_json

def generate_password(length):
  return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(int(length)))

def post_password(api_url, sesh, user, new_pass):
  # maybe add a user lookup here?
  get_user = sesh.get(f"{api_url}/users/{user}").json()
  post_user = sesh.post(f"{api_url}/users/{user}?password={new_pass}").json()
  print(post_user)

def reset_password(api_url, sesh):
  new_pass = generate_password(8)
  # user_uri = 
  post_pass = post_password(api_url, sesh, new_pass)

'''
Get user data
'''

def lookup_user(api_url, sesh, user_lookup):
  # eventually make this repeat...
  uname = input('Please enter a name to look up (Firstname Lastname): ')
  # add error handling
  user_uri = user_lookup.get(f'{uname}').get('uri')
  print(f"URI for {uname}: {user_uri}")
  user_data = get_user(api_url, sesh, user_uri)
  return user_data

def get_list_of_user_ids(api_url, sesh):
  return sesh.get(f"{api_url}/users?all_ids=True").json()

def chunks(data, n):
  return [data[i:i + n] for i in range(0, len(data), n)]

def get_users(api_url, sesh, all_ids):
  return sesh.get(f"{api_url}/users?id_set={str(all_ids).replace('[', '').replace(']', '')}").json()

def user_datastore(api_url, sesh):
  '''Generates user data on login to facilitate user-related data manipulation

     NOTE: these user records are not complete, they do not contain the actual list of permissions;
     I think you need to actually get the user detail to do that. But this can be the basis of getting a lookup table
  '''
  user_dataset = []
  user_list = get_list_of_user_ids(api_url, sesh)
  chunked_users = chunks(user_list, 250)
  for chunked_user in chunked_users:
    user_data = get_users(api_url, sesh, chunked_user)
    user_dataset.extend(user_data)
  return user_dataset

def user_lookup_table(api_url, sesh, name=False):
  '''Can use this directly by doing:

  lookup_table = user_lookup_table(api_url, sesh)
  user_uri = lookup_table.get('amd243').get('uri')

  '''
  datastore = user_datastore(api_url, sesh)
  #pprint.pprint(datastore)
  if name == False:
    return {item.get('username'): {'name': item.get('name'), 'uri': item.get('uri')} 
              for item in datastore}
  else:
    return {item.get('name'): {'name': item.get('username'), 'uri': item.get('uri')} 
              for item in datastore}

def get_list_of_repos(api_url, sesh):
  return sesh.get(f"{api_url}/repositories").json()

def repo_lookup_table(api_url, sesh):
  '''Can call like so:

  repo_lookup = repo_lookup_table(api_url, sesh)
  repo_uri = repo_lookup.get('MSSA')
  '''
  datastore = get_list_of_repos(api_url, sesh)
  return {item.get('repo_code'): item.get('uri') for item in datastore}

def filter_permissions(permissions):
  permissions_by_level = defaultdict(list)
  for item in permissions:
    permissions_by_level[item.get('level')].append(item.get('permission_code'))
  return permissions_by_level

def get_list_of_permissions(api_url, sesh, level='all'):
  '''Level can be repository, global, all; default is all'''
  permissions = sesh.get(f"{api_url}/permissions?level={level}").json()
  return filter_permissions(permissions)

def filter_groups(groups):
  return {group.get('group_code'): {'uri': group.get('uri'), 'grants_permissions': group.get('grants_permissions')} for group in groups}

def group_lookup_table(api_url, sesh, repo_uri):
  '''This does not include the list of usernames...so will need to look those up'''
  groups = sesh.get(f"{api_url}{repo_uri}/groups").json()
  return filter_groups(groups)

def get_user(api_url, sesh, user_uri):
  return sesh.get(f"{api_url}{user_uri}").json()

def get_group(api_url, sesh, group_uri):
  return sesh.get(f"{api_url}{group_uri}").json()

def search_users():
  '''Presuming that this is possible, should mimic the function below'''
  pass

def search_agents(api_url, sesh, username, title=False):
  '''Looks up a user by net ID or full name.

     Might want to return either the full user record, or just the URI?

     Right now this just returns the agent record, not the user record. But
     searching on type user did not work. Not sure how to do that. Possibly the
     best way would be just to return the user datastore every session and 
     then change the lookup user function to search that...

  '''
  if title == False:
    results = sesh.get(f"{api_url}/search?page=1&type[]=agent_person&q=notes:NetID: {username}").json()
  else:
    results = sesh.get(f"{api_url}/search?page=1&type[]=agent_person&q=title:{username}").json()
  if results.get('total_hits') == 1:
    return results.get('results')
  elif results.get('total_hits') > 1:
    raise 'More than one result'
  elif results.get('total_hits') == 0:
    raise 'No hits'

'''
Assessment group permission functions - may want to abstract these or something.
'''

def group_helper(api_url, uri, value):
  '''Helper function for update_assessment_group'''
  get_group = sesh.get(f"{api_url}{uri}").json()
  for username in value:
    get_group['member_usernames'].append(username)
    post_group = requests.post(f"{api_url}{uri}", headers=headers, json=get_group).json()
    print(post_group)

def update_assessment_group(defdict, api_url, headers):
  '''Updates the existing assessment group with new usernames'''
  for key, value in defdict.items():
    if key == '11':
      group_uri = '/repositories/11/groups/284'
      group_helper(api_url, headers, group_uri, value)
    if key == '12':
      group_uri = '/repositories/12/groups/285'
      group_helper(api_url, headers, group_uri, value)

def prep_user_groups(data):
  '''Data in a list of lists with each row being ['user_uri', 'username', 'repo']

     Output:

     defaultdict(<class 'list'>,
            {'10': ['mg824', 'mel79', 'ccz2', 'kei7', 'cma79', 'mmp85'],
             '11': ['mf55',
                    'kmarinuz',
                    'lc449',
                    'rc264',
                    'sd332']}
  '''
  defdict = defaultdict(list)
  for row in data:
    repo_id = row[2]
    defdict[repo_id].append(row[1])
  return defdict

def create_assessment_groups(defdict):
  '''Prepares a new assessment group

  Output:

  [{'description': 'Create, read, update and delete assessment records',
  'grants_permissions': ['update_assessment_record',
                         'delete_assessment_record'],
  'group_code': 'assessments',
  'jsonmodel_type': 'group',
  'member_usernames': ['em956', 'dlb29'],
  'repository': {'ref': '/repositories/14'}},
 {'description': 'Create, read, update and delete assessment records',
  'grants_permissions': ['update_assessment_record',
                         'delete_assessment_record'],
  'group_code': 'assessments',
  'jsonmodel_type': 'group',
  'member_usernames': ['lfg2'],
  'repository': {'ref': '/repositories/15'}}]

  '''
  new_groups = []
  for key, value in defdict.items():
    if key not in ('11', '12'):
      new_group = {'jsonmodel_type': 'group', 'group_code': 'assessments', 'description': 'Create, read, update and delete assessment records', 'grants_permissions': ['update_assessment_record', 'delete_assessment_record'], 'repository': {'ref': f'/repositories/{key}'}, 'member_usernames': value}
      new_groups.append(new_group)
  return new_groups

def post_new_groups(api_url, sesh, new_groups):
  '''Posts output of create_assessment_groups function'''
  for item in new_groups:
    repo_uri = item['repository']['ref']
    req = sesh.post(f"{api_url}{repo_uri}/groups", json=item).json()
    print(req)

''' 
Connection functions.
'''

def get_config_data(cfg):
  api_url = cfg.get('api_url')
  username = cfg.get('username')
  password = cfg.get('password')
  return api_url, username, password

def login(url=None, username=None, password=None):
    """Logs into the ArchivesSpace API"""
    try:
        if url is None or username is None or password is None:
            url = input('Please enter the ArchivesSpace API URL: ')
            username = input('Please enter your username: ')
            password = input('Please enter your password: ')
        auth = requests.post(url+'/users/'+username+'/login?password='+password).json()
        #if session object is returned then login was successful; if not it failed.
        if 'session' in auth:
            session = auth["session"]
            h = {'X-ArchivesSpace-Session':session, 'Content_Type': 'application/json'}
            print('Login successful!')
            return (url, h)
        else:
            print('Login failed! Check credentials and try again.')
            u, heads = login()
            return u, heads
    except:
        print('Login failed! Check credentials and try again!')
        u, heads = login()
        return u, heads

def set_session():
  with open('config.json', 'r', encoding='utf8') as cfg_file:
    cfg = json.load(cfg_file)
    login_url, username, password = get_config_data(cfg)
    api_url, headers = login(url=login_url, username=username, password=password)
    sesh = requests.Session()
    sesh.headers.update(headers)
    return api_url, sesh

def main():
  pass


if __name__ == "__main__":
  main()


'''

Don't recall if I used an SQL query to get some of this data beforehand...probably??? Is there a way I can get the same data via the API?

Relevant endpoints:

/current_global_preferences GET Get the global Preferences records for the current user.

/repositories/:id GET Get a Repository by ID
/repositories/:repo_id/current_preferences  GET Get the Preferences records for the current repository and user.
/repositories/:repo_id/groups POST  Create a group within a repository


/repositories/:repo_id/groups/:id POST  Update a group
/repositories/:repo_id/groups/:id GET Get a group by ID
/repositories/:repo_id/groups/:id DELETE  Delete a group by ID
/repositories/:repo_id/preferences  POST  Create a Preferences record
/repositories/:repo_id/preferences  GET Get a list of Preferences for a Repository and optionally a user
/repositories/:repo_id/preferences/:id  GET Get a Preferences record
/repositories/:repo_id/preferences/:id  POST  Update a Preferences record
/repositories/:repo_id/preferences/:id  DELETE  Delete a Preferences record
/repositories/:repo_id/preferences/defaults GET Get the default set of Preferences for a Repository and optionally a user
/repositories/:repo_id/users/:id  GET Get a user’s details including their groups for the current repository
/users  POST  Create a local user
/users/:id  GET Get a user’s details (including their current permissions)
/users/:id  POST  Update a user’s account
/users/:id  DELETE  Delete a user
/users/:id/groups POST  Update a user’s groups
/users/:username/become-user  POST  Become a different user
/users/:username/login  POST  Log in
/users/complete GET Get a list of system users
/users/current-user GET Get the currently logged in user'''