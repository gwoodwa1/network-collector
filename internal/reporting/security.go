package reporting

import "github.com/gwoodwa1/network-collector/internal/safeoutput"

func sanitizeModel(model Model) Model {
	model.Title = safeoutput.Sanitize(model.Title)
	model.ChangeReference = safeoutput.Sanitize(model.ChangeReference)
	model.RunID = safeoutput.Sanitize(model.RunID)
	model.Playbook = safeoutput.Sanitize(model.Playbook)
	model.Devices = append([]Device(nil), model.Devices...)
	for index := range model.Devices {
		model.Devices[index].Hostname = safeoutput.Sanitize(model.Devices[index].Hostname)
		model.Devices[index].IP = safeoutput.Sanitize(model.Devices[index].IP)
	}
	model.FailedValidations = append([]Validation(nil), model.FailedValidations...)
	for index := range model.FailedValidations {
		item := &model.FailedValidations[index]
		item.Hostname = safeoutput.Sanitize(item.Hostname)
		item.Check = safeoutput.Sanitize(item.Check)
		item.Condition = safeoutput.Sanitize(item.Condition)
		item.Expected = safeoutput.Sanitize(item.Expected)
		item.Value = safeoutput.Sanitize(item.Value)
		item.Message = safeoutput.Sanitize(item.Message)
	}
	model.Changes = append([]Change(nil), model.Changes...)
	for index := range model.Changes {
		item := &model.Changes[index]
		item.Hostname = safeoutput.Sanitize(item.Hostname)
		item.Step = safeoutput.Sanitize(item.Step)
		item.Resource = safeoutput.Sanitize(item.Resource)
		item.Platform = safeoutput.Sanitize(item.Platform)
		item.Action = safeoutput.Sanitize(item.Action)
		item.Current = safeoutput.Sanitize(item.Current)
		item.Desired = safeoutput.Sanitize(item.Desired)
		item.RollbackStatus = safeoutput.Sanitize(item.RollbackStatus)
		item.Evidence = safeoutput.Sanitize(item.Evidence)
		item.Commands = append([]string(nil), item.Commands...)
		for commandIndex := range item.Commands {
			item.Commands[commandIndex] = safeoutput.Sanitize(item.Commands[commandIndex])
		}
	}
	model.Triggers = append([]Trigger(nil), model.Triggers...)
	for index := range model.Triggers {
		item := &model.Triggers[index]
		item.Hostname = safeoutput.Sanitize(item.Hostname)
		item.Step = safeoutput.Sanitize(item.Step)
		item.Path = safeoutput.Sanitize(item.Path)
		item.Value = safeoutput.Sanitize(item.Value)
		item.Metric = safeoutput.Sanitize(item.Metric)
		item.Threshold = safeoutput.Sanitize(item.Threshold)
	}
	model.Timeline = append([]TimelineEvent(nil), model.Timeline...)
	for index := range model.Timeline {
		item := &model.Timeline[index]
		item.Hostname = safeoutput.Sanitize(item.Hostname)
		item.Step = safeoutput.Sanitize(item.Step)
		item.Type = safeoutput.Sanitize(item.Type)
		item.Summary = safeoutput.Sanitize(item.Summary)
	}
	model.Artifacts = append([]Artifact(nil), model.Artifacts...)
	for index := range model.Artifacts {
		item := &model.Artifacts[index]
		item.Hostname = safeoutput.Sanitize(item.Hostname)
		item.Step = safeoutput.Sanitize(item.Step)
		item.Kind = safeoutput.Sanitize(item.Kind)
		item.Path = safeoutput.Sanitize(item.Path)
	}
	model.Warnings = append([]string(nil), model.Warnings...)
	for index := range model.Warnings {
		model.Warnings[index] = safeoutput.Sanitize(model.Warnings[index])
	}
	return model
}
