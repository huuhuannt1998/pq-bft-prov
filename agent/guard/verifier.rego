# Deterministic smart-home safety verifier (IoT-J revision).
#
# This is the mechanism the paper calls load-bearing, so it is specified and evaluated rather than
# asserted. It is evaluated OUTSIDE any model, on a structured action + context record, and returns
# one of permit / escalate / deny together with the rule ids that fired.
#
# Precedence is fixed and total: deny > escalate > permit. A rule may only make the outcome more
# restrictive, so rule order cannot change a decision and conflicts cannot silently resolve to permit.
#
# Trust: every context field is supplied by the gateway from device/sensor state, never by the model
# and never parsed out of ingested content. Fields carry an age; stale or missing state for a
# high-risk or critical action is a denial or an escalation, never a silent permit (see F1-F3).
#
# Input:
# {
#   "action":  {"device","domain","command","args","risk_tier"},
#   "context": {"occupancy":{"value","age_s"}, "time_hhmm", "authenticated", "device_state",
#               "sensors", "recent_unlocks", "last_action_age_s", "guest_window", "interlocks"}
# }
package pqbftprov.verifier

import rego.v1

action := input.action
ctx := input.context
dev := lower(object.get(action, "device", ""))
cmd := lower(object.get(action, "command", ""))
dom := lower(object.get(action, "domain", ""))
tier := lower(object.get(action, "risk_tier", "low"))

off_cmds := {"turn_off", "disable", "off", "stop"}
on_cmds := {"turn_on", "enable", "on", "start"}

# ---------------------------------------------------------------- life safety (LS)

deny_rules contains "LS1" if {
	regex.match(`smoke`, dev)
	cmd in off_cmds
}

deny_rules contains "LS2" if {
	regex.match(`carbon|co_|co2|gas`, dev)
	cmd in off_cmds
}

deny_rules contains "LS3" if {
	regex.match(`notify|notification|alert`, dev)
	cmd in off_cmds
	object.get(action, ["args", "critical"], false) == true
}

escalate_rules contains "LS4" if {
	regex.match(`alarm`, dev)
	cmd in {"override", "silence", "snooze"}
}

# LS5 covers any component the operator declared required, sensor or protective device. The earlier
# device-name regex was the wrong test: it missed cameras and pumps that the declared set already names.
required_components := {lower(s) | some s in array.concat(
	object.get(ctx, ["required_sensors"], []),
	object.get(ctx, ["required_devices"], []))}

deny_rules contains "LS5" if {
	cmd in off_cmds
	dev in required_components
}

# ---------------------------------------------------------------- access control (AC)

deny_rules contains "AC1" if {
	regex.match(`all_doors|every_door|\.all$|all_locks`, dev)
	cmd in {"unlock", "open", "turn_on"}
}

deny_rules contains "AC2" if {
	dom == "lock"
	cmd in {"unlock", "open"}
	object.get(ctx, ["occupancy", "value"], "unknown") == "away"
	object.get(ctx, "authenticated", false) == false
}

escalate_rules contains "AC3" if {
	dom == "lock"
	cmd in {"unlock", "open"}
	night
}

deny_rules contains "AC4" if {
	dom == "lock"
	cmd in {"unlock", "open"}
	count(object.get(ctx, "recent_unlocks", [])) >= 3
}

deny_rules contains "AC5" if {
	dom == "lock"
	object.get(ctx, ["guest_window", "active"], true) == false
	object.get(action, ["args", "actor"], "") == "guest"
}

deny_rules contains "AC6" if {
	regex.match(`security_system|alarm_system`, dev)
	cmd in {"disarm", "turn_off", "disable"}
}

# ---------------------------------------------------------------- appliance safety (AP)

deny_rules contains "AP1" if {
	dom == "climate"
	to_number(object.get(action, ["args", "target_c"], 0)) > to_number(object.get(ctx, "max_setpoint_c", 30))
}

deny_rules contains "AP2" if {
	regex.match(`boiler|water_heater`, dev)
	cmd in on_cmds
	object.get(ctx, ["device_state", "fault"], false) == true
}

deny_rules contains "AP3" if {
	regex.match(`stove|oven|cooktop|boiler|water_heater|space_heater|fireplace|pool_heater`, dev)
	cmd in on_cmds
	object.get(ctx, ["occupancy", "value"], "unknown") == "away"
}

deny_rules contains "AP4" if {
	cmd in on_cmds
	to_number(object.get(action, ["args", "duration_s"], 0)) > to_number(object.get(ctx, "max_duration_s", 7200))
}

deny_rules contains "AP5" if {
	cmd in on_cmds
	some req in object.get(ctx, ["interlocks", "required"], [])
	object.get(ctx, ["interlocks", "satisfied"], []) != []
	not req in object.get(ctx, ["interlocks", "satisfied"], [])
}

deny_rules contains "AP5" if {
	cmd in on_cmds
	object.get(ctx, ["interlocks", "required"], []) != []
	object.get(ctx, ["interlocks", "satisfied"], []) == []
}

# ---------------------------------------------------------------- sensor integrity (SI)

deny_rules contains "SI1" if {
	tier in {"high", "critical"}
	to_number(object.get(ctx, ["occupancy", "age_s"], 0)) > to_number(object.get(ctx, "max_state_age_s", 300))
}

escalate_rules contains "SI2" if {
	object.get(ctx, ["sensors", "conflict"], false) == true
}

deny_rules contains "SI3" if {
	tier == "critical"
	object.get(ctx, ["occupancy", "value"], "unknown") == "unknown"
}

escalate_rules contains "SI3" if {
	tier == "high"
	object.get(ctx, ["occupancy", "value"], "unknown") == "unknown"
}

deny_rules contains "SI4" if {
	tier in {"high", "critical"}
	object.get(ctx, "state_authenticated", true) == false
}

# ---------------------------------------------------------------- temporal / sequential (TS)

night if {
	t := object.get(ctx, "time_hhmm", "12:00")
	hh := to_number(substring(t, 0, 2))
	hh >= 23
}

night if {
	t := object.get(ctx, "time_hhmm", "12:00")
	hh := to_number(substring(t, 0, 2))
	hh < 6
}

deny_rules contains "TS1" if {
	object.get(action, ["args", "night_restricted"], false) == true
	night
}

deny_rules contains "TS2" if {
	to_number(object.get(ctx, "last_action_age_s", 999999)) < to_number(object.get(ctx, "cooldown_s", 0))
}

deny_rules contains "TS3" if {
	some p in object.get(ctx, ["prerequisites", "required"], [])
	not p in object.get(ctx, ["prerequisites", "met"], [])
}

deny_rules contains "TS4" if {
	to_number(object.get(ctx, "toggles_last_minute", 0)) >= 5
}

# ---------------------------------------------------------------- decision

default decision := "permit"

decision := "deny" if count(deny_rules) > 0

decision := "escalate" if {
	count(deny_rules) == 0
	count(escalate_rules) > 0
}

result := {
	"decision": decision,
	"deny_rules": sort([r | some r in deny_rules]),
	"escalate_rules": sort([r | some r in escalate_rules]),
}
