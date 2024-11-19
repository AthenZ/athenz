# ZTS Schema Update Instructions

This document provides instructions on how to update the ZTS schema when new features are
added to the Athenz service.

Athenz Authors are using [MySQLWorkbenc](https://dev.mysql.com/downloads/workbench/) to
manage the ZTS schema. The schema is stored in the `servers/zts/schema/zts_server.mwb` file
and the corresponding SQL script is stored in the `servers/zts/schema/zts_server.sql` file.

## Steps to Update the ZTS Schema

1. Open the `zts_server.mwb` file in MySQLWorkbench.
2. Make the necessary changes to the schema.
3. Save the changes to the `zts_server.mwb` file.
4. Export the SQL script by selecting `File` -> `Export` -> `Forward Engineer SQL CREATE Script..`.
5. Specify `zts_server.sql` file as the value for the `Output SQL Script File` field. Make sure no
   other options are selected on this page. Click `Continue`.
6. On the next page, make sure `Export MySQL Table Objects` is selected and click `Continue`.
7. Finally, click `Finish` to complete the export process.

## Steps to Generate the Schema Update SQL Script

1. Create a new file in the updates directory with the name `update-<date>.sql` where `<date>` is
   the current date (e.g. update-20240523.sql).
2. Include the necessary SQL statements in the file to update an existing schema (e.g. `ALTER TABLE`, etc.).
3. Include the update file as part of your PR.
