# SVID store suite

## Description

This suite validates the core logic of the SVID store feature. It uses a custom SVIDStore plugin that stores the SVIDs in disk.
The suite is composed of the following tests:

1. Start spire server and agent loading the custom plugin used for testing.
2. Create registration entries with and without the `storeSVID` flag.
3. Check that the required SVIDs are stored in the file.
4. Update entries, removing the `storeSVID` flag from the ones that has it, and adding it to the ones that don't.
5. Check that the required SVIDs are stored in the file.
6. Delete all entries.
7. Check that the file is empty.
