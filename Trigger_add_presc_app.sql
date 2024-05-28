CREATE OR REPLACE FUNCTION add_prescription_app()
RETURNS TRIGGER AS $$
DECLARE
    patient_id UUID;
BEGIN

    SELECT patient_person_id INTO patient_id FROM appointment WHERE id = NEW.appointment_id;
    
    INSERT INTO prescription_patient (prescription_id, patient_person_id) VALUES (NEW.prescription_id, patient_id);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_add_prescription_app on public.prescription_appointment;

CREATE TRIGGER trigger_add_prescription_app
AFTER INSERT ON prescription_appointment
FOR EACH ROW
EXECUTE FUNCTION add_prescription_app();