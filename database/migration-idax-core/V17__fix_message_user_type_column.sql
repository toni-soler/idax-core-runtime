ALTER TABLE idax_core.idax_message_user
    ALTER COLUMN message_type TYPE VARCHAR(1)
    USING message_type::VARCHAR(1);
