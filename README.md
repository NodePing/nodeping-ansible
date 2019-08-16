# NodePing Ansible module

The NodePing Ansible module lets you create, get, update, and delete checks all
from Ansible! This means as you're setting up or modifying servers, you can also
manage your checks.

## Getting Started

To use this module, you will have to place the `nodeping.py` file in your
modules directory (the `library` variable in your ansible.cfg file). In addition,
you will have to have the nodeping-api library installed on the system that
will be handling your NodePing checks. You can install the library with pip:

`pip install nodeping-api`

The repository can be found [here](https://github.com/NodePing/python-nodeping-api)

It is recommended that you configure your playbook to create/update/delete checks
from the host you are running your playbooks from (shown in examples below). This is
suggested for the simplicity and so your API token will not be sent to the various
systems you are deploying over SSH.

## Examples

Here are a couple examples below. There is also a sample playbook provided in this
repository.

### Running Locally

This method will allow you to run your playbooks on your remote machines that you are
building, but you won't need the nodeping-api code installed on your remote machines.
This is done by delegating the nodeping tasks to localhost.

``` yaml
---
- hosts: test
  
  vars:
    mytoken: secret-token-here
    
  tasks:
    - name: Create a check for current host
      delegate_to: localhost
      nodeping:
        action: create
        checktype: PING
        target: "{{ ansible_default_ipv4.address }}"
        label: mytest ping
        enabled: False
        interval: 1
        token: "{{ mytoken }}"
        notifications:
        - group: My Contact Group
          notifydelay: 2
          notifyschedule: All the time
        - contact: 4QT82
          notifydelay: 0
          notifyschedule: All the time
```

### Running Remotely

This method doesn't require you to include the `delegate_to` and variables
for each `nodeping` task, but it will require that the Python nodeping-api is installed
remotely on each machine.

``` yaml
- hosts: test

  vars:
    mytoken: secret-token-here
    
  tasks:
    - name: Install pip for your system
      package:
        name: python-pip
        state: present
        
    - name: Install nodeping-api
      pip:
        name: nodeping-api
        state: present
        
    - name: Test create an HTTP check
      nodeping:
        action: create
        checktype: HTTP
        target: "http://{{ ansible_default_ipv4.address }}"
        label: test http
        interval: 3
        token: "{{ mytoken }}"
        notifications:
        - group: testgroup
          notifydelay: 2
          notifyschedule: All the time
        - contact: 4QT82
          notifydelay: 0
          notifyschedule: All the time
        - name: I renamed this
          address: me@example.com
          notifydelay: 0
          notifyschedule: Nights
```

### Getting a Check by Label

Sometimes you are required to get a check by a label. However, keep in mind
you can have many checks with the same label, and there is no guarantee you
will be working with the check you're thinking of. If you plan to manage
checks by label, you have to ensure you have checks with no duplicate labels.
Otherwise, it is most prudent to get checks by their ID.

``` yaml
- hosts: test

  vars:
    mytoken: secret-token-here
    
  tasks:
    - name: Get check by its label
      nodeping:
        action: get
        label: my-checks-label
        token: "{{ mytoken }}"
```

You can then register the result and use the information you retrieved.

### Getting a Check by ID

This is the recommended method of getting a check, since there are no two
checks with the same ID.

``` yaml
- hosts: test

  vars:
    mytoken: secret-token-here
    
  tasks:
    - name: Get check by its label
      nodeping:
        action: get
        checkid: your-checkid
        token: "{{ mytoken }}"
```
