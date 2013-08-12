minion-breach-plugin
====================

This is a Minion plugin for determining whether a site is vulnerable to BREACH.

Plan
----

There is no optional configuration. A BREACH plan is as simple as:

```
[
  {
    "configuration": {},
    "description": "",
    "plugin_name": "minion.plugins.breach.BreachPlugin"
  }
]
```
