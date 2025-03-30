class ConsentManager:
    def __init__(self):
        self.consents = {}

    def grant_access(self, patient_id: str, provider_id: str) -> None:
        if patient_id not in self.consents:
            self.consents[patient_id] = {}
        self.consents[patient_id][provider_id] = True

    def revoke_access(self, patient_id: str, provider_id: str) -> None:
        if patient_id in self.consents and provider_id in self.consents[patient_id]:
            del self.consents[patient_id][provider_id]

    def has_access(self, patient_id: str, provider_id: str) -> bool:
        return self.consents.get(patient_id, {}).get(provider_id, False)