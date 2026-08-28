DROP POLICY IF EXISTS p_idax_message_header_admin ON idax_core.idax_message_header;
CREATE POLICY p_idax_message_header_admin ON idax_core.idax_message_header
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS p_idax_message_user_admin ON idax_core.idax_message_user;
CREATE POLICY p_idax_message_user_admin ON idax_core.idax_message_user
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS p_idax_message_attachment_admin ON idax_core.idax_message_attachment;
CREATE POLICY p_idax_message_attachment_admin ON idax_core.idax_message_attachment
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS p_idax_message_group_admin ON idax_core.idax_message_group;
CREATE POLICY p_idax_message_group_admin ON idax_core.idax_message_group
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS p_idax_message_group_member_admin ON idax_core.idax_message_group_member;
CREATE POLICY p_idax_message_group_member_admin ON idax_core.idax_message_group_member
FOR ALL TO idax_admin
USING (true)
WITH CHECK (true);
