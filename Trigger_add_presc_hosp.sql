CREATE OR REPLACE FUNCTION add_prescription_hosp()
RETURNS TRIGGER AS $$
DECLARE
    patient_id UUID;
BEGIN

    SELECT patient_person_id INTO patient_id FROM hospitalization WHERE id = NEW.hospitalization_id;
    
    INSERT INTO prescription_patient (prescription_id, patient_person_id) VALUES (NEW.prescription_id, patient_id);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_add_prescription_hosp on public.hospitalization_prescription;

CREATE TRIGGER trigger_add_prescription_hosp
AFTER INSERT ON hospitalization_prescription
FOR EACH ROW
EXECUTE FUNCTION add_prescription_hosp();