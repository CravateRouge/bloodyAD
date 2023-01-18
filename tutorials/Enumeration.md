# Enumeration with BloodyAD

## Get AD forest level
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getObjectAttributes 'DC=crash,DC=lab' msDS-Behavior-Version
{
    "msDS-Behavior-Version": "DS_BEHAVIOR_WIN2016"
}
```

## Get Machine Account Quota (MAQ)
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getObjectAttributes 'DC=crash,DC=lab' ms-DS-MachineAccountQuota                     
{
    "ms-DS-MachineAccountQuota": 10
}
```

## Get Kerberoastable accounts
```

```