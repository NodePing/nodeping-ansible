#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, NodePing LLC <support@nodeping.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import inspect
import traceback
from time import time
from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {
    "metadata_version": "3.0",
    "status": ["stableinterface"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: nodeping

short_description: Manage your NodePing checks

version_added: "2.5"

description:
    - This module will let you get, create, update, or delete checks on your NodePing account
requirements:
    - "The NodePing Python library: https://github.com/NodePing/nodepingpy"

options:
  token:
    description:
      - Your API token for your NodePing account
    type: str
  customerid:
    description:
      - The ID for your subaccount
    type: str
  checktype:
    description:
      - The type of check that will be created
      - Examples include PING, HTTP, SSL, DNS
    type: str
  checkid:
    description:
      - The ID of an already existing check
    type: str
  label:
    description:
      - The name you choose for your check
    type: str
  target:
    description:
      - URL or FQDN for check target
    type: str
  action:
    description:
      - Whether you want to get, create, update, or delete an existing check
      - With getting, updating, and deleting checks, you will have to supply a checkid
    choices: [ get, create, update, delete ]
    type: str
    required: true
  interval:
    description:
      - How often this check runs in minutes
    type: int
    default: 15
  enabled:
    description:
      - If the check should be enabled or not
    type: bool
    default: yes
  public:
    description:
      - If yes public reports will be enabled for this check
    type: bool
    default: no
  runlocations:
    description:
      - Which region to run your checks from
      - type: str
      - choices: [ nam, eur, eao, lam, wlw ]
    type: str
  homeloc:
    description:
      - Which probe to run your check from (Provider plan only)
      - A list of probes can be found here https://nodeping.com/faq.html
      - Use the abbreviation (such as WA for Seattle, WA location)
    type: str
  threshold:
    description:
      - the timeout for this check in seconds
    default: 5
    type: int
  sens:
    description:
      - number of rechecks before this check is considered 'down' or 'up'
    default: 2
    type: int
  dep:
    description:
      - the id of the check used for the notification dependency
    type: str
  mute:
    description:
      - optional boolean or millisecond timestamp or day (D), hour (H), minutes (M) or seconds (S) mute from now
      - True mutes all notifications
      - 5D = 5 day mute, 3H = 3 hour mute, 30M = 30 minute mute, 180S = 180 second mute
    default: false
    type: str
  description:
    description:
      - optional string. Can put arbitrary text, JSON, XML, etc. Size limit 1000 characters
    type: str
  checktoken:
    description:
      - read-only field on PUSH checks
      - Can reset this token by setting this value to 'reset'
    type: str
  clientcert:
    description:
      - specify the ID of a client certificate/key to be used in the DOHDOT check
    type: str
  contentstring:
    description:
      - The string to match the response against.
      - For DNS, HTTPCONTENT, HTTPADV, FTP, SSH, WEBSOCKET, WHOIS type checks
    type: str
  dohdot:
    description:
      - string used to specify if DoH or DoT in the DOHDOT check.
    default: doh
    type: str
  dnssection:
    description:
      - case-sensitive string for which section of the DNS reply to look in for the contentstring match
      - values: answer, authority, additional, edns_options
    default: answer
    type: str
  dnstype:
    description:
      - Optional string for DNS checks to indicate the type of DNS entry to query
      - String set to one of: 'ANY', 'A', 'AAAA', 'CNAME', 'MX, 'NS, 'PTR', 'SOA', 'TXT'.
    type: str
  dnstoresolve:
    description:
      - optional string for DNS type checks - The FQDN of the DNS query
    type: str
  dnsrd:
    description:
      - optional boolean for DNS RD (Recursion Desired) bit.
      - If you're using CloudFlare DNS servers, set this to no.
    default: yes
    type: bool
  transport:
    description:
      - optional string for DNS transport protocol
    type: str
    default: udp
    choices: [ tcp, udp ]
  follow:
    description:
      - Used for HTTP, HTTPCONTENT and HTTPADV checks.
      - If true, the check will follow up to four redirects
      - The HTTPADV check only supports follow for GET requests.
    type: bool
  email:
    description:
      - Used for IMAP and SMTP checks.
    type: str
  port:
    description:
      - Required integer for DNS, FTP, NTP, PORT, SSH type checks.
      - Used for check types that support port fields separate from the target address.
      - HTTP and HTTPCONTENT will ignore this field as the port must be set in the target in standard URL format.
    type: int
  username:
    description:
      - String used for FTP, IMAP, POP, SMTP and SSH type checks.
      - HTTP and HTTPCONTENT will ignore this field as the username must be set in the target in standard URL format.
    type: str
  password:
    description:
      - String used for FTP, IMAP, POP, SMTP and SSH type checks.
      - Note that this is going to be passed back and forth in the data, so you should always be sure that credentials used for checks are very limited in their access level.
    type: str
  query:
    description:
      - optional string for PGSQL and MYSQL check types. SQL query to send to the database server
    type: str
  secure:
    description:
      - Specify whether the IMAP, SMTP, and POP checks should use TLS for the check.
    type: bool
  sshkey:
    description:
      - specify the ID of an SSH private key to be used in the SSH check
    type: str
  verify:
    description:
      - Set whether or not to verify the certificate
    type: bool
  hosts:
    description:
      - Object for specifying host information for the redis check
      - Example: "hosts": {"HSGWNS": {"host": "redis1.example.com", "port": 6379}}
    type: dict
  ignore:
    description:
      - Optional string for the RBL check type, specifies RBL lists to ignore.
      - Multiple lists can be added to be ignored.
    type: str
  invert:
    description:
      - Optional string for FTP, HTTPCONTENT, HTTPADV, NTP, PORT, SSH type checks
      - Used for 'Does not contain' functionality in checks.
    default: no
    type: bool
  warningdays:
    description:
      - Optional integer for SSL, WHOIS, POP, IMAP, and SMTP checks
      - Number of days before certificate (or domain for WHOIS) expiration to fail the check and send a notification.
    type: int
  fields:
    description:
      - optional object used for fields to parse from the HTTPADV, HTTPPARSE, and SNMP response.
      - This is a keyed list of fields, with an arbitrary (by default random) string as the key.
      - Each object in the list should include three elements: name, min and max.
    type: dict
  postdata:
    description:
      - Optional string that can be used in the HTTPADV check as an alternative to the data object.
      - Postdata should be a single string to post.
    type: str
  data:
    description:
      - Optional objects used by HTTPADV ('data') can also be used for CLUSTER.
      - They are formatted as key:value pairs.
    type: dict
  websocketdata:
    description:
      - Data that will be sent to the websocket
    type: str
  database:
    description:
      - name of database
    type: str
  edns:
    description:
      - used to send EDNS(0) OPT pseudo-records in a DNS query in the DOHDOT check type
    type: dict
  receiveheaders:
    description:
      - Optional objects used by HTTPADV ('data' can also be used for CLUSTER.
      - They are formatted as key:value pairs.
    type: dict
  sendheaders:
    description:
      - Optional objects used by HTTPADV ('data' can also be used for CLUSTER.
      - They are formatted as key:value pairs.
    type: dict
  method:
    description:
      - optional string used by the HTTPADV check to specify the HTTP method.
    type: str
    choices: [GET, POST, PUT, HEAD, TRACE, CONNECT]
  statuscode:
    description:
      - Optional integer specifying the expected status code in the response to an HTTPADV check.
    type: int
  ipv6:
    description:
      - Specify if the check should run against an ipv6 address.
      - PING, HTTP, HTTPCONTENT, HTTPADV, WHOIS checks.
    type: bool
  redistype:
    description:
      - Values: standalone, sentinel, or cluster
    type: str
  regex:
    description:
      - treat 'contentstring' as a regular expression if true
    type: bool
  sentinelname:
    description:
      - required if redistype is "sentinel"
      - Set to the "master name" that is in your sentinel configuration
    type: str
  servername:
    description:
      - FQDN sent to SNI services in the SSL check
    type: str
  snmpv:
    description:
      - String specifying the SNMP version the check should use.
    type: str
    default: 1
    choices: [1, 2c]
  snmpcom:
    description:
      - String specifying the SNMP community indicator that should be used.
    type: str
    default: public
  verifyvolume:
    description:
      - Enable the volume detection feature - AUDIO check only.
    type: bool
  volumemin:
    description:
      - acceptable range -90 to 0, used by the volume detection feature - AUDIO check only.
    type: int
  whoisserver:
    description:
     - Specify the WHOIS server FQDN or IPv(4/6) to query - WHOIS check only.
    type: str
  notifications:
    description:
      - A single contact/contact group made with a list of dictionaries
  notifydelay:
    description:
      - If there should be any delay in minutes for notifications
    default: 0
    type: int
  notifyschedule:
    description:
      - The schedule you want to use for notifications
    default: All the time
    type: str


author:
    - NodePing (@nodeping)
"""

EXAMPLES = """
# Create a ping check to check every minute with single contact
- name: Create a ping check with 3 minute notification delay
  nodeping:
    action: create
    checktype: PING
    label: ping_my_host
    target: example.com
    interval: 1
    enabled: yes
    runlocations: nam
    notifications:
      - name: My Email
        address: me@example.com
        notifydelay: 3
        notifyschedule: All the time
      - group: My Group
        notifydelay: 0
        notifyschedule: Nights
      - contact: BKPGH
        notifydelay: 0
        notifyschedule: Days
      - group: 201205050153W2Q4C-G-3QJWG
        notifydelay: 15
        notifyschedule: All the time

# Create a DNS check with a contact group for notifications with Daytime alerts
- name: Create DNS check to check every 5 minutes
  nodeping:
    action: create
    checktype: DNS
    label: dns_query
    target: ns1.example.com
    interval: 5
    dnstype: A
    dnstoresolve: example.com
    contentstring: 123.231.100.5
    notifications:
    - group: mygroup
      notifydelay: 0
      notifyschedule: Daytime

# Modify a check based on its checkid
- name: Modify an existing check to ping IPv6
  nodeping:
    action: update
    checkid: 201205050153W2Q4C-0J2HSIRF
    ipv6: yes

# Delete a check
- name: Delete this check based on its ID
  nodeping:
    action: delete
    checkid: 201205050153W2Q4C-0J2HSIRF
"""

RETURN = """
original_message:
    description: The original name param that was passed in
    type: str
    returned: always
message:
    description: The response that NodePing returns after a check is created/updated/deleted
    type: dict
    returned: always
"""


NODEPING_IMPORT_ERROR = None

try:
    import nodepingpy
except ImportError:
    NODEPING_IMPORT_ERROR = traceback.format_exc()
    IMPORTED_NODEPING_API = False
else:
    IMPORTED_NODEPING_API = True


def get_nodeping_check(parameters):
    """Get the user defined check by its checkid."""
    token = parameters["token"]
    customerid = parameters["customerid"]
    checkid = parameters["checkid"]

    if checkid and checkid.lower() == "all":
        result = nodepingpy.checks.get_all(token, customerid)
    elif checkid:
        result = nodepingpy.checks.get_by_id(token, checkid, customerid)
    elif parameters["label"] and not checkid:
        get_checks = nodepingpy.checks.get_all(token, customerid)
        for _, value in get_checks.items():
            if value["label"] == parameters["label"]:
                result = value
                break
            else:
                result = {"error": "Check ID label not found"}
    else:
        result = nodepingpy.checks.get_all(token, customerid)

    try:
        result.update({"changed": True})
    except KeyError:
        result.update({"changed": False})
        return (False, checkid, result)
    else:
        return (True, checkid, result)


def create_nodeping_check(parameters):
    """Create a NodePing check."""
    token = parameters["token"]
    customerid = parameters["customerid"]
    name = parameters["label"] or parameters["target"]
    checktype = parameters["checktype"].upper()
    classname = "{}Check".format(checktype.title())
    (_, checkclass) = [
        func
        for func in inspect.getmembers(nodepingpy.checktypes)
        if inspect.isclass(func[1]) and func[0] == classname
    ][0]

    # websocketdata isn't part of the API but is necessary to get the data in
    # string format for the 'data' key. This is a workaround to ensure the
    # NodePing API gets the expected data key, and make sure the Ansible
    # module is happy with the other `data` keys that are a dict.
    if checktype == "WEBSOCKET":
        parameters.update({"data": parameters["websocketdata"]})
        del parameters["websocketdata"]

    if parameters["mute"]:
        parameters.update({"mute": set_mute_timestamp(parameters["mute"])})

    # Get contacts & notification schedules if they exist
    if parameters["notifications"]:
        notifications = parameters["notifications"]

        if not isinstance(notifications, list):
            notifications = [notifications]

        parameters.update(
            {"notifications": convert_contacts(notifications, token, customerid)}
        )

    args_dict = {}
    check_keys = checkclass.__annotations__.keys()

    for key in parameters.keys():
        if key in check_keys:
            args_dict.update({key: parameters[key]})

    result = nodepingpy.checks.create_check(token, checkclass(**args_dict), customerid)

    try:
        created = bool(result["created"])
        result.update({"changed": True})
    except KeyError:
        result.update({"changed": False})
        return (False, name, result)
    else:
        return (created, name, result)


def update_nodeping_check(parameters):
    """Update an existing NodePing check."""
    update_fields = {}
    changed = False

    token = parameters["token"]
    check_id = parameters["checkid"]
    label = parameters["label"]
    customerid = parameters["customerid"]
    check_info = nodepingpy.checks.get_by_id(token, check_id, customerid)
    checktype = check_info["type"]

    # Removes all values that are not provided by the user
    stripped_params = {
        key: value for (key, value) in parameters.items() if value is not None
    }

    for key, value in check_info.items():
        try:
            # The new value provided by the user to compare to
            # The value the check currently has
            compare = stripped_params[key]
        except KeyError:
            if not isinstance(value, dict):
                continue

        # Compare nested dictionaries for differences
        # (eg ipv6, sens, target, threshold)
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                try:
                    compare = stripped_params[subkey]
                except KeyError:
                    continue

                if subvalue != compare:
                    changed = True
                    update_fields.update({subkey: compare})

            continue

        # Required to properly update the data field for WEBSOCKET checks
        if checktype == "WEBSOCKET" and parameters["websocketdata"]:
            update_fields.update({"data": parameters["websocketdata"]})

        # Replace the old notifications with the newly provided ones
        if key == "notifications":
            update_fields.update(
                {
                    "notifications": convert_contacts(
                        parameters["notifications"], token, customerid
                    )
                }
            )

            continue

        if key == "mute":
            mute = set_mute_timestamp(stripped_params["mute"])

            if mute != check_info["mute"]:
                changed = True
                update_fields.update({"mute": mute})

            continue

        # Always pass the provided dependency because not passing it will
        # remove the dependency from the existing check
        if key == "dep":
            update_fields.update({"dep": compare})
            continue

        # If the value is different, add the change
        if value != compare:
            changed = True
            update_fields.update({key: compare})

    if "enabled" in stripped_params.keys():
        enabled = stripped_params["enabled"]
        if enabled is True:
            check_enable = "active"
            ret_enabled = "true"
        elif enabled is False:
            check_enable = "inactive"
            ret_enabled = "false"
        else:
            check_enable = "inactive"
            ret_enabled = "false"

        if check_enable != check_info["enable"]:
            changed = True

        update_fields.update({"enabled": ret_enabled})

    # Update the check
    result = nodepingpy.checks.update_check(
        token, check_id, checktype, update_fields, customerid
    )
    result.update({"changed": changed})

    try:
        result["error"]
    except KeyError:
        return (True, "%s changed" % label, result)
    else:
        return (False, check_id, result)


def delete_nodeping_check(parameters):
    """Delete an existing NodePing check."""
    token = parameters["token"]
    checkid = parameters["checkid"]
    customerid = parameters["customerid"]

    result = nodepingpy.checks.delete_check(token, checkid, customerid)

    try:
        result["error"]
    except KeyError:
        return (True, checkid, result)
    else:
        return (False, checkid, result)


def convert_contacts(notification_contacts, token, customerid):
    """Take in a contact/group list and converts to the expected IDs"""

    # notification_contacts [{'contact': 'RCMXLQR8', 'notifydelay': 0, 'notifyschedule': 'All the time'}]
    all_contacts = []
    account_contacts = account_groups = {}
    #account_notificationprofiles = {}

    for contact in notification_contacts:
        if "name" in contact.keys():
            if not account_contacts:
                account_contacts = nodepingpy.contacts.get_all(token, customerid)

            for _, value in account_contacts.items():
                if contact["name"] == value["name"]:
                    for key, address in value["addresses"].items():
                        if address["address"] == contact["address"]:
                            all_contacts += [
                                {
                                    key: {
                                        "schedule": contact["notifyschedule"],
                                        "delay": contact["notifydelay"]
                                    }
                                }
                            ]
        elif "group" in contact.keys():
            if not account_contacts:
                account_groups = nodepingpy.contactgroups.get_all(token, customerid)

            for key, value in account_groups.items():
                if value["name"] == contact["group"] or key == contact["group"]:
                    all_contacts += [
                        {
                            key: {
                                "schedule": contact["notifyschedule"],
                                "delay": contact["notifydelay"]
                            }
                        }
                    ]
        #elif (
        #    "notificationprofile" in contact.keys() and not account_notificationprofiles
        #):
        #    account_notificationprofiles = nodepingpy.notificationprofiles.get_all(
        #        token, customerid
        #    )
        elif "contact" in contact.keys():
            all_contacts += [{contact["contact"]: {"schedule": contact["notifyschedule"], "delay": contact["notifydelay"]}}]
        else:
            continue

    return all_contacts


def set_mute_timestamp(mute):
    """Convert Mute time to timestamp"""

    if isinstance(mute, int):
        return mute
    else:
        if mute.upper().endswith("D"):
            return int(time() * 1000) + (int(mute[:-1]) * 86400000)
        elif mute.upper().endswith("H"):
            return int(time() * 1000) + (int(mute[:-1]) * 3600000)
        elif mute.upper().endswith("M"):
            return int(time() * 1000) + (int(mute[:-1]) * 60000)
        elif mute.upper().endswith("S"):
            return int(time() * 1000) + int(mute[:-1])
        elif mute.upper() == "TRUE" or mute.upper() == "YES":
            return True
        elif mute.upper() == "FALSE" or mute.upper() == "NO":
            return False
        else:
            return False


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        token=dict(type="str", required=True, no_log=True),
        customerid=dict(type="str", required=False),
        checktype=dict(type="str", required=False),
        checkid=dict(type="str", required=False),
        label=dict(type="str", required=False),
        target=dict(type="str", required=False),
        action=dict(
            type="str", required=True, choices=["get", "create", "update", "delete"]
        ),
        interval=dict(type="int", required=False),
        enabled=dict(type="bool", required=False),
        public=dict(type="bool", required=False),
        runlocations=dict(type="str", required=False),
        homeloc=dict(type="str", required=False),
        threshold=dict(type="int", required=False),
        sens=dict(type="int", required=False),
        dep=dict(type="str", required=False),
        mute=dict(type="str", required=False, default="off"),
        description=dict(type="str", required=False),
        checktoken=dict(type="str", required=False),
        clientcert=dict(type="str", required=False),
        contentstring=dict(type="str", required=False),
        dohdot=dict(type="str", required=False),
        dnssection=dict(type="str", required=False),
        dnstype=dict(type="str", required=False),
        dnstoresolve=dict(type="str", required=False),
        dnsrd=dict(type="bool", required=False),
        transport=dict(type="str", required=False, choices=["udp", "tcp"]),
        follow=dict(type="bool", required=False),
        email=dict(type="str", required=False),
        port=dict(type="int", required=False),
        username=dict(type="str", required=False),
        password=dict(type="str", required=False, no_log=True),
        query=dict(type="str", required=False),
        secure=dict(type="bool", required=False),
        sshkey=dict(type="str", required=False),
        verify=dict(type="bool", required=False),
        hosts=dict(type="dict", required=False),
        ignore=dict(type="str", required=False),
        invert=dict(type="bool", required=False),
        warningdays=dict(type="int", required=False),
        fields=dict(type="dict", required=False),
        postdata=dict(type="str", required=False),
        data=dict(type="dict", required=False),
        websocketdata=dict(type="str", required=False),
        receiveheaders=dict(type="dict", required=False),
        sendheaders=dict(type="dict", required=False),
        database=dict(type="str", required=False),
        edns=dict(type="dict", required=False),
        method=dict(
            type="str",
            required=False,
            choices=["GET", "POST", "PUT", "HEAD", "TRACE", "CONNECT"],
        ),
        statuscode=dict(type="int", required=False),
        ipv6=dict(type="bool", required=False),
        redistype=dict(type="str", required=False),
        regex=dict(type="str", required=False),
        sentinelname=dict(type="str", required=False),
        servername=dict(type="str", required=False),
        snmpv=dict(type="str", required=False, choices=["1", "2c"]),
        snmpcom=dict(type="str", required=False),
        verifyvolume=dict(type="bool", required=False),
        volumein=dict(type="int", required=False),
        whoisserver=dict(type="str", required=False),
        notifications=dict(type="list", required=False),
        notifydelay=dict(type="int", required=False),
        notifyschedule=dict(type="str", required=False),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(changed=False, original_message="", message="")

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not IMPORTED_NODEPING_API:
        module.fail_json(
            msg="Missing import lib: nodepingpy", exception=NODEPING_IMPORT_ERROR
        )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    params = module.params

    action = params["action"]

    if action == "get":
        status, label, output = get_nodeping_check(params)

        if not status:
            module.fail_json(
                msg="Failed to get checkid %s" % params["checkid"], **output
            )
    elif action == "create":
        checktype = params["checktype"]

        # If user specified to create a check, but not the type
        # a check cannot be made
        if not checktype:
            module.fail_json(msg="No Check Type specified for check creation")

        status, label, output = create_nodeping_check(params)

        if not status:
            module.fail_json(msg="Failed to create %s" % label, **output)

    elif action == "update":
        if not params["checkid"]:
            module.fail_json(msg="No checkid specified for updating check")

        status, label, output = update_nodeping_check(params)

        if not status:
            module.fail_json(msg="Failed to update %s" % label, **output)

    elif action == "delete":
        if not params["checkid"]:
            module.fail_json(msg="No checkid provided to delete a check")

        status, label, output = delete_nodeping_check(params)

        if not status:
            module.fail_json(
                msg="Failed to delete checkid %s" % params["checkid"], **output
            )

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result["original_message"] = ""
    result["message"] = output

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    try:
        output["changed"]
    except KeyError:
        result["changed"] = False
    else:
        result["changed"] = output.pop("changed")

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    # if result['changed'] == False:
    #     module.fail_json(msg='You requested this to fail', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
