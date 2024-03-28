#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, NodePing LLC <support@nodeping.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import traceback
from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {
    "metadata_version": "3.0",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: nodeping_maintenance

short_description: Create scheduled or ad-hoc maintence schedules

version_added: "2.9"

description:
    - This module allows you to create maintenance schedules that are
      ad-hoc and only run once, or will operate at a recurring schedule.
      More info on maintenance can be found here:
      https://nodeping.com/docs-api-maintenance.html
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
  checklist:
    description:
      - The list of checks that will be disabled when the maintenance schedule begins
    type: list
  name:
    description:
      - The name of the maintenance schedule
    type: str
  enabled:
    description:
      - Whether or not the maintenance will be enabled (True for ad-hoc)
    type: bool
  duration:
    description:
      - How long the maintenance will last once it is initiated
    type: int
  cron:
    description:
      - Cron expression for when a scheduled maintenance will start
    type: str
  scheduled:
    description:
      - Whether the maintenance should be scheduled (True) or ad-hoc (False)
    type: bool

author:
    - NodePing (@nodeping)
"""

EXAMPLES = """
---
- hosts: localhost

  vars:
    nodeping_api_token: your-token-here

  tasks:
    - name: Create ad-hoc maintenance
      delegate_to: localhost
      nodeping_maintenance:
        token: "{{ nodeping_api_token }}"
        name: ad-hoc maintenance
        duration: 30
        scheduled: False
        checklist:
          - 201911191441YC6SJ-4S9OJ78G
          - 201911191441YC6SJ-XB5HUTG6

    - name: Create maintenance schedule
      delegate_to: localhost
      nodeping_maintenance:
        token: "{{ nodeping_api_token }}"
        name: scheduled maintenance
        scheduled: True
        duration: 60
        cron: 5 0 * 8 *
        checklist:
          - 201911191441YC6SJ-4S9OJ78G
          - 201911191441YC6SJ-XB5HUTG6
"""

RETURN = """
original_message:
    description: The original name param that was passed in
    type: str
    returned: always
message:
    description: The response that NodePing returns after a maintenance is created
    type: dict
    returned: always
"""


NODEPING_IMPORT_ERROR = None

try:
    from nodepingpy import maintenance
    from nodepingpy.nptypes import maintenancetypes
except ImportError:
    NODEPING_IMPORT_ERROR = traceback.format_exc()
    IMPORTED_NODEPING_API = False
else:
    IMPORTED_NODEPING_API = True


def configure_maintenance(parameters):
    """Create a scheduled or ad-hoc maintenance."""

    if parameters["scheduled"]:
        args_dict = generate_data(
            parameters, maintenancetypes.ScheduledCreate.__annotations__.keys()
        )
        data = maintenancetypes.ScheduledCreate(**args_dict)
    else:
        args_dict = generate_data(
            parameters, maintenancetypes.AdHocCreate.__annotations__.keys()
        )
        data = maintenancetypes.AdHocCreate(**args_dict)

    result = maintenance.create(parameters["token"], data, parameters["customerid"])

    if "error" in result.keys():
        result.update({"changed": False})
        return (False, parameters["name"], result)
    else:
        result.update({"changed": True})
        return (True, parameters["name"], result)


def generate_data(parameters, matchkeys):
    return_dict = {}
    for key in parameters.keys():
        if key in matchkeys:
            return_dict.update({key: parameters[key]})

    return return_dict


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        token=dict(type="str", required=True, no_log=True),
        customerid=dict(type="str", required=False),
        checklist=dict(type="list", required=True),
        name=dict(type="str", required=True),
        enabled=dict(type="bool", required=False, default=True),
        duration=dict(type="int", required=True),
        cron=dict(type="str", required=False),
        scheduled=dict(type="bool", required=True),
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

    status, label, output = configure_maintenance(params)

    if not status:
        module.fail_json(msg="Failed to create status %s" % label, **output)

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
