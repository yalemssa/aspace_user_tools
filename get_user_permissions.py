#/usr/bin/python3

import pprint
import aspace_user_tools as utools

def main():
  api_url, sesh = utools.set_session()
  print(f"Connected to: {api_url}")
  user_lookup = utools.user_lookup_table(api_url, sesh, name=True)
  do_it_again = True
  while do_it_again == True:
    user = utools.lookup_user(api_url, sesh, user_lookup)
    pprint.pprint(user)
    get_user_input = input('Enter any key to look up another user. Enter Q to quit: ')
    if get_user_input == 'Q':
      do_it_again = False


if __name__ == "__main__":
  main()