REM Macro generated to clean up: Neo_Relique_SILVER_Master_Line_Sheet.xlsx
REM This macro will delete rows where columns F, G, H, and I are all empty or zero
REM Generated on: 2025-09-11 03:58:10 UTC

Sub DeleteEmptyRows()
    Dim oDoc As Object
    Dim oSheet As Object
    Dim oController As Object
    Dim i As Long
    Dim rowsDeleted As Long
    
    ' Get the current document and controller
    oDoc = ThisComponent
    oController = oDoc.getCurrentController()
    
    ' Disable screen updating for performance (LibreOffice syntax)
    oController.getFrame().getContainerWindow().setEnable(False)
    
    ' Show initial message
    Print "Starting row deletion process..."
    Print "Processing 11 sheet(s)..."
    
    rowsDeleted = 0

    ' Process sheet: STUDS
    Print "Processing sheet: STUDS (22 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("STUDS") Then
        oSheet = oDoc.Sheets.getByName("STUDS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 43 to 54 (12 rows)
        oSheet.Rows.removeByIndex(42, 12)
        rowsDeleted = rowsDeleted + 12
        Print "  ✓ Deleted 12 rows starting at row 43"
        
        ' Delete rows 38 to 39 (2 rows)
        oSheet.Rows.removeByIndex(37, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 38"
        
        ' Delete rows 33 to 33 (1 row)
        oSheet.Rows.removeByIndex(32, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 33"
        
        ' Delete rows 30 to 30 (1 row)
        oSheet.Rows.removeByIndex(29, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 30"
        
        ' Delete rows 28 to 28 (1 row)
        oSheet.Rows.removeByIndex(27, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 28"
        
        ' Delete rows 26 to 26 (1 row)
        oSheet.Rows.removeByIndex(25, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 26"
        
        ' Delete rows 21 to 21 (1 row)
        oSheet.Rows.removeByIndex(20, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 21"
        
        ' Delete rows 17 to 19 (3 rows)
        oSheet.Rows.removeByIndex(16, 3)
        rowsDeleted = rowsDeleted + 3
        Print "  ✓ Deleted 3 rows starting at row 17"
        
        Print "  → Completed sheet 'STUDS'"
    Else
        Print "  ⚠ Warning: Sheet 'STUDS' not found"
    End If

    ' Process sheet: FASHION EARS
    Print "Processing sheet: FASHION EARS (10 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("FASHION EARS") Then
        oSheet = oDoc.Sheets.getByName("FASHION EARS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 24 to 24 (1 row)
        oSheet.Rows.removeByIndex(23, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 24"
        
        ' Delete rows 18 to 19 (2 rows)
        oSheet.Rows.removeByIndex(17, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 18"
        
        ' Delete rows 14 to 15 (2 rows)
        oSheet.Rows.removeByIndex(13, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 14"
        
        ' Delete rows 11 to 11 (1 row)
        oSheet.Rows.removeByIndex(10, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 11"
        
        ' Delete rows 5 to 7 (3 rows)
        oSheet.Rows.removeByIndex(4, 3)
        rowsDeleted = rowsDeleted + 3
        Print "  ✓ Deleted 3 rows starting at row 5"
        
        ' Delete rows 3 to 3 (1 row)
        oSheet.Rows.removeByIndex(2, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 3"
        
        Print "  → Completed sheet 'FASHION EARS'"
    Else
        Print "  ⚠ Warning: Sheet 'FASHION EARS' not found"
    End If

    ' Process sheet: HOOPS
    Print "Processing sheet: HOOPS (8 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("HOOPS") Then
        oSheet = oDoc.Sheets.getByName("HOOPS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 55 to 55 (1 row)
        oSheet.Rows.removeByIndex(54, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 55"
        
        ' Delete rows 43 to 44 (2 rows)
        oSheet.Rows.removeByIndex(42, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 43"
        
        ' Delete rows 28 to 29 (2 rows)
        oSheet.Rows.removeByIndex(27, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 28"
        
        ' Delete rows 12 to 12 (1 row)
        oSheet.Rows.removeByIndex(11, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 12"
        
        ' Delete rows 9 to 10 (2 rows)
        oSheet.Rows.removeByIndex(8, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 9"
        
        Print "  → Completed sheet 'HOOPS'"
    Else
        Print "  ⚠ Warning: Sheet 'HOOPS' not found"
    End If

    ' Process sheet: CASE.CARDED EARS
    Print "Processing sheet: CASE.CARDED EARS (14 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("CASE.CARDED EARS") Then
        oSheet = oDoc.Sheets.getByName("CASE.CARDED EARS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 57 to 57 (1 row)
        oSheet.Rows.removeByIndex(56, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 57"
        
        ' Delete rows 55 to 55 (1 row)
        oSheet.Rows.removeByIndex(54, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 55"
        
        ' Delete rows 52 to 53 (2 rows)
        oSheet.Rows.removeByIndex(51, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 52"
        
        ' Delete rows 43 to 46 (4 rows)
        oSheet.Rows.removeByIndex(42, 4)
        rowsDeleted = rowsDeleted + 4
        Print "  ✓ Deleted 4 rows starting at row 43"
        
        ' Delete rows 38 to 38 (1 row)
        oSheet.Rows.removeByIndex(37, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 38"
        
        ' Delete rows 29 to 30 (2 rows)
        oSheet.Rows.removeByIndex(28, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 29"
        
        ' Delete rows 25 to 26 (2 rows)
        oSheet.Rows.removeByIndex(24, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 25"
        
        ' Delete rows 23 to 23 (1 row)
        oSheet.Rows.removeByIndex(22, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 23"
        
        Print "  → Completed sheet 'CASE.CARDED EARS'"
    Else
        Print "  ⚠ Warning: Sheet 'CASE.CARDED EARS' not found"
    End If

    ' Process sheet: COSTUME EARS
    Print "Processing sheet: COSTUME EARS (6 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("COSTUME EARS") Then
        oSheet = oDoc.Sheets.getByName("COSTUME EARS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 21 to 26 (6 rows)
        oSheet.Rows.removeByIndex(20, 6)
        rowsDeleted = rowsDeleted + 6
        Print "  ✓ Deleted 6 rows starting at row 21"
        
        Print "  → Completed sheet 'COSTUME EARS'"
    Else
        Print "  ⚠ Warning: Sheet 'COSTUME EARS' not found"
    End If

    ' Process sheet: BX NECKS
    Print "Processing sheet: BX NECKS (10 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("BX NECKS") Then
        oSheet = oDoc.Sheets.getByName("BX NECKS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 22 to 29 (8 rows)
        oSheet.Rows.removeByIndex(21, 8)
        rowsDeleted = rowsDeleted + 8
        Print "  ✓ Deleted 8 rows starting at row 22"
        
        ' Delete rows 10 to 11 (2 rows)
        oSheet.Rows.removeByIndex(9, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 10"
        
        Print "  → Completed sheet 'BX NECKS'"
    Else
        Print "  ⚠ Warning: Sheet 'BX NECKS' not found"
    End If

    ' Process sheet: OS RINGS
    Print "Processing sheet: OS RINGS (2 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("OS RINGS") Then
        oSheet = oDoc.Sheets.getByName("OS RINGS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 26 to 27 (2 rows)
        oSheet.Rows.removeByIndex(25, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 26"
        
        Print "  → Completed sheet 'OS RINGS'"
    Else
        Print "  ⚠ Warning: Sheet 'OS RINGS' not found"
    End If

    ' Process sheet: BRACELETS
    Print "Processing sheet: BRACELETS (7 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("BRACELETS") Then
        oSheet = oDoc.Sheets.getByName("BRACELETS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 72 to 73 (2 rows)
        oSheet.Rows.removeByIndex(71, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 72"
        
        ' Delete rows 69 to 69 (1 row)
        oSheet.Rows.removeByIndex(68, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 69"
        
        ' Delete rows 53 to 53 (1 row)
        oSheet.Rows.removeByIndex(52, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 53"
        
        ' Delete rows 49 to 50 (2 rows)
        oSheet.Rows.removeByIndex(48, 2)
        rowsDeleted = rowsDeleted + 2
        Print "  ✓ Deleted 2 rows starting at row 49"
        
        ' Delete rows 4 to 4 (1 row)
        oSheet.Rows.removeByIndex(3, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 4"
        
        Print "  → Completed sheet 'BRACELETS'"
    Else
        Print "  ⚠ Warning: Sheet 'BRACELETS' not found"
    End If

    ' Process sheet: CASE BROOCH
    Print "Processing sheet: CASE BROOCH (19 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("CASE BROOCH") Then
        oSheet = oDoc.Sheets.getByName("CASE BROOCH")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 54 to 61 (8 rows)
        oSheet.Rows.removeByIndex(53, 8)
        rowsDeleted = rowsDeleted + 8
        Print "  ✓ Deleted 8 rows starting at row 54"
        
        ' Delete rows 43 to 52 (10 rows)
        oSheet.Rows.removeByIndex(42, 10)
        rowsDeleted = rowsDeleted + 10
        Print "  ✓ Deleted 10 rows starting at row 43"
        
        ' Delete rows 37 to 37 (1 row)
        oSheet.Rows.removeByIndex(36, 1)
        rowsDeleted = rowsDeleted + 1
        Print "  ✓ Deleted 1 row starting at row 37"
        
        Print "  → Completed sheet 'CASE BROOCH'"
    Else
        Print "  ⚠ Warning: Sheet 'CASE BROOCH' not found"
    End If

    ' Process sheet: OS BROOCH
    Print "Processing sheet: OS BROOCH (12 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("OS BROOCH") Then
        oSheet = oDoc.Sheets.getByName("OS BROOCH")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 40 to 48 (9 rows)
        oSheet.Rows.removeByIndex(39, 9)
        rowsDeleted = rowsDeleted + 9
        Print "  ✓ Deleted 9 rows starting at row 40"
        
        ' Delete rows 36 to 38 (3 rows)
        oSheet.Rows.removeByIndex(35, 3)
        rowsDeleted = rowsDeleted + 3
        Print "  ✓ Deleted 3 rows starting at row 36"
        
        Print "  → Completed sheet 'OS BROOCH'"
    Else
        Print "  ⚠ Warning: Sheet 'OS BROOCH' not found"
    End If

    ' Process sheet: BAG CHARM
    Print "Processing sheet: BAG CHARM (12 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("BAG CHARM") Then
        oSheet = oDoc.Sheets.getByName("BAG CHARM")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 33 to 41 (9 rows)
        oSheet.Rows.removeByIndex(32, 9)
        rowsDeleted = rowsDeleted + 9
        Print "  ✓ Deleted 9 rows starting at row 33"
        
        ' Delete rows 29 to 31 (3 rows)
        oSheet.Rows.removeByIndex(28, 3)
        rowsDeleted = rowsDeleted + 3
        Print "  ✓ Deleted 3 rows starting at row 29"
        
        Print "  → Completed sheet 'BAG CHARM'"
    Else
        Print "  ⚠ Warning: Sheet 'BAG CHARM' not found"
    End If

    ' Re-enable screen updates
    oController.getFrame().getContainerWindow().setEnable(True)
    
    ' Show completion message
    Print "Process completed successfully!"
    Print "Total rows deleted: " & rowsDeleted
    
    ' Final completion dialog
    MsgBox "Row deletion completed!" & Chr(10) & Chr(10) & _
           "✓ Total rows deleted: " & rowsDeleted & Chr(10) & _
           "✓ All images and formatting preserved" & Chr(10) & Chr(10) & _
           "Please save your file now (Ctrl+S).", _
           64, "Process Complete"
    
End Sub

REM Silent version without dialogs:
Sub DeleteEmptyRowsSilent()
    Dim oDoc As Object
    Dim oSheet As Object
    Dim oController As Object
    Dim rowsDeleted As Long
    
    ' Get document and disable screen updates
    oDoc = ThisComponent
    oController = oDoc.getCurrentController()
    oController.getFrame().getContainerWindow().setEnable(False)
    
    rowsDeleted = 0

    ' Process sheet: STUDS
    REM "Processing sheet: STUDS (22 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("STUDS") Then
        oSheet = oDoc.Sheets.getByName("STUDS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 43 to 54 (12 rows)
        oSheet.Rows.removeByIndex(42, 12)
        rowsDeleted = rowsDeleted + 12
        REM "  ✓ Deleted 12 rows starting at row 43"
        
        ' Delete rows 38 to 39 (2 rows)
        oSheet.Rows.removeByIndex(37, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 38"
        
        ' Delete rows 33 to 33 (1 row)
        oSheet.Rows.removeByIndex(32, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 33"
        
        ' Delete rows 30 to 30 (1 row)
        oSheet.Rows.removeByIndex(29, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 30"
        
        ' Delete rows 28 to 28 (1 row)
        oSheet.Rows.removeByIndex(27, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 28"
        
        ' Delete rows 26 to 26 (1 row)
        oSheet.Rows.removeByIndex(25, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 26"
        
        ' Delete rows 21 to 21 (1 row)
        oSheet.Rows.removeByIndex(20, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 21"
        
        ' Delete rows 17 to 19 (3 rows)
        oSheet.Rows.removeByIndex(16, 3)
        rowsDeleted = rowsDeleted + 3
        REM "  ✓ Deleted 3 rows starting at row 17"
        
        REM "  → Completed sheet 'STUDS'"
    Else
        REM "  ⚠ Warning: Sheet 'STUDS' not found"
    End If

    ' Process sheet: FASHION EARS
    REM "Processing sheet: FASHION EARS (10 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("FASHION EARS") Then
        oSheet = oDoc.Sheets.getByName("FASHION EARS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 24 to 24 (1 row)
        oSheet.Rows.removeByIndex(23, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 24"
        
        ' Delete rows 18 to 19 (2 rows)
        oSheet.Rows.removeByIndex(17, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 18"
        
        ' Delete rows 14 to 15 (2 rows)
        oSheet.Rows.removeByIndex(13, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 14"
        
        ' Delete rows 11 to 11 (1 row)
        oSheet.Rows.removeByIndex(10, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 11"
        
        ' Delete rows 5 to 7 (3 rows)
        oSheet.Rows.removeByIndex(4, 3)
        rowsDeleted = rowsDeleted + 3
        REM "  ✓ Deleted 3 rows starting at row 5"
        
        ' Delete rows 3 to 3 (1 row)
        oSheet.Rows.removeByIndex(2, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 3"
        
        REM "  → Completed sheet 'FASHION EARS'"
    Else
        REM "  ⚠ Warning: Sheet 'FASHION EARS' not found"
    End If

    ' Process sheet: HOOPS
    REM "Processing sheet: HOOPS (8 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("HOOPS") Then
        oSheet = oDoc.Sheets.getByName("HOOPS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 55 to 55 (1 row)
        oSheet.Rows.removeByIndex(54, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 55"
        
        ' Delete rows 43 to 44 (2 rows)
        oSheet.Rows.removeByIndex(42, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 43"
        
        ' Delete rows 28 to 29 (2 rows)
        oSheet.Rows.removeByIndex(27, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 28"
        
        ' Delete rows 12 to 12 (1 row)
        oSheet.Rows.removeByIndex(11, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 12"
        
        ' Delete rows 9 to 10 (2 rows)
        oSheet.Rows.removeByIndex(8, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 9"
        
        REM "  → Completed sheet 'HOOPS'"
    Else
        REM "  ⚠ Warning: Sheet 'HOOPS' not found"
    End If

    ' Process sheet: CASE.CARDED EARS
    REM "Processing sheet: CASE.CARDED EARS (14 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("CASE.CARDED EARS") Then
        oSheet = oDoc.Sheets.getByName("CASE.CARDED EARS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 57 to 57 (1 row)
        oSheet.Rows.removeByIndex(56, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 57"
        
        ' Delete rows 55 to 55 (1 row)
        oSheet.Rows.removeByIndex(54, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 55"
        
        ' Delete rows 52 to 53 (2 rows)
        oSheet.Rows.removeByIndex(51, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 52"
        
        ' Delete rows 43 to 46 (4 rows)
        oSheet.Rows.removeByIndex(42, 4)
        rowsDeleted = rowsDeleted + 4
        REM "  ✓ Deleted 4 rows starting at row 43"
        
        ' Delete rows 38 to 38 (1 row)
        oSheet.Rows.removeByIndex(37, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 38"
        
        ' Delete rows 29 to 30 (2 rows)
        oSheet.Rows.removeByIndex(28, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 29"
        
        ' Delete rows 25 to 26 (2 rows)
        oSheet.Rows.removeByIndex(24, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 25"
        
        ' Delete rows 23 to 23 (1 row)
        oSheet.Rows.removeByIndex(22, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 23"
        
        REM "  → Completed sheet 'CASE.CARDED EARS'"
    Else
        REM "  ⚠ Warning: Sheet 'CASE.CARDED EARS' not found"
    End If

    ' Process sheet: COSTUME EARS
    REM "Processing sheet: COSTUME EARS (6 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("COSTUME EARS") Then
        oSheet = oDoc.Sheets.getByName("COSTUME EARS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 21 to 26 (6 rows)
        oSheet.Rows.removeByIndex(20, 6)
        rowsDeleted = rowsDeleted + 6
        REM "  ✓ Deleted 6 rows starting at row 21"
        
        REM "  → Completed sheet 'COSTUME EARS'"
    Else
        REM "  ⚠ Warning: Sheet 'COSTUME EARS' not found"
    End If

    ' Process sheet: BX NECKS
    REM "Processing sheet: BX NECKS (10 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("BX NECKS") Then
        oSheet = oDoc.Sheets.getByName("BX NECKS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 22 to 29 (8 rows)
        oSheet.Rows.removeByIndex(21, 8)
        rowsDeleted = rowsDeleted + 8
        REM "  ✓ Deleted 8 rows starting at row 22"
        
        ' Delete rows 10 to 11 (2 rows)
        oSheet.Rows.removeByIndex(9, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 10"
        
        REM "  → Completed sheet 'BX NECKS'"
    Else
        REM "  ⚠ Warning: Sheet 'BX NECKS' not found"
    End If

    ' Process sheet: OS RINGS
    REM "Processing sheet: OS RINGS (2 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("OS RINGS") Then
        oSheet = oDoc.Sheets.getByName("OS RINGS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 26 to 27 (2 rows)
        oSheet.Rows.removeByIndex(25, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 26"
        
        REM "  → Completed sheet 'OS RINGS'"
    Else
        REM "  ⚠ Warning: Sheet 'OS RINGS' not found"
    End If

    ' Process sheet: BRACELETS
    REM "Processing sheet: BRACELETS (7 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("BRACELETS") Then
        oSheet = oDoc.Sheets.getByName("BRACELETS")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 72 to 73 (2 rows)
        oSheet.Rows.removeByIndex(71, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 72"
        
        ' Delete rows 69 to 69 (1 row)
        oSheet.Rows.removeByIndex(68, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 69"
        
        ' Delete rows 53 to 53 (1 row)
        oSheet.Rows.removeByIndex(52, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 53"
        
        ' Delete rows 49 to 50 (2 rows)
        oSheet.Rows.removeByIndex(48, 2)
        rowsDeleted = rowsDeleted + 2
        REM "  ✓ Deleted 2 rows starting at row 49"
        
        ' Delete rows 4 to 4 (1 row)
        oSheet.Rows.removeByIndex(3, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 4"
        
        REM "  → Completed sheet 'BRACELETS'"
    Else
        REM "  ⚠ Warning: Sheet 'BRACELETS' not found"
    End If

    ' Process sheet: CASE BROOCH
    REM "Processing sheet: CASE BROOCH (19 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("CASE BROOCH") Then
        oSheet = oDoc.Sheets.getByName("CASE BROOCH")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 54 to 61 (8 rows)
        oSheet.Rows.removeByIndex(53, 8)
        rowsDeleted = rowsDeleted + 8
        REM "  ✓ Deleted 8 rows starting at row 54"
        
        ' Delete rows 43 to 52 (10 rows)
        oSheet.Rows.removeByIndex(42, 10)
        rowsDeleted = rowsDeleted + 10
        REM "  ✓ Deleted 10 rows starting at row 43"
        
        ' Delete rows 37 to 37 (1 row)
        oSheet.Rows.removeByIndex(36, 1)
        rowsDeleted = rowsDeleted + 1
        REM "  ✓ Deleted 1 row starting at row 37"
        
        REM "  → Completed sheet 'CASE BROOCH'"
    Else
        REM "  ⚠ Warning: Sheet 'CASE BROOCH' not found"
    End If

    ' Process sheet: OS BROOCH
    REM "Processing sheet: OS BROOCH (12 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("OS BROOCH") Then
        oSheet = oDoc.Sheets.getByName("OS BROOCH")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 40 to 48 (9 rows)
        oSheet.Rows.removeByIndex(39, 9)
        rowsDeleted = rowsDeleted + 9
        REM "  ✓ Deleted 9 rows starting at row 40"
        
        ' Delete rows 36 to 38 (3 rows)
        oSheet.Rows.removeByIndex(35, 3)
        rowsDeleted = rowsDeleted + 3
        REM "  ✓ Deleted 3 rows starting at row 36"
        
        REM "  → Completed sheet 'OS BROOCH'"
    Else
        REM "  ⚠ Warning: Sheet 'OS BROOCH' not found"
    End If

    ' Process sheet: BAG CHARM
    REM "Processing sheet: BAG CHARM (12 rows to delete)"
    
    ' Get sheet by name
    If oDoc.Sheets.hasByName("BAG CHARM") Then
        oSheet = oDoc.Sheets.getByName("BAG CHARM")
        
        ' Delete rows from bottom to top to maintain row numbers
        
        ' Delete rows 33 to 41 (9 rows)
        oSheet.Rows.removeByIndex(32, 9)
        rowsDeleted = rowsDeleted + 9
        REM "  ✓ Deleted 9 rows starting at row 33"
        
        ' Delete rows 29 to 31 (3 rows)
        oSheet.Rows.removeByIndex(28, 3)
        rowsDeleted = rowsDeleted + 3
        REM "  ✓ Deleted 3 rows starting at row 29"
        
        REM "  → Completed sheet 'BAG CHARM'"
    Else
        REM "  ⚠ Warning: Sheet 'BAG CHARM' not found"
    End If

    ' Re-enable screen
    oController.getFrame().getContainerWindow().setEnable(True)
    
    ' Just print to console - no dialog
    Print "Silent deletion completed. Rows deleted: " & rowsDeleted
    
End Sub

REM INSTRUCTIONS FOR USE:
REM 
REM Option 1 - With completion dialog (recommended):
REM   1. Run "DeleteEmptyRows"
REM   2. Watch progress in console (View -> Basic IDE if not visible)
REM   3. One final confirmation when complete
REM
REM Option 2 - Completely silent:
REM   1. Run "DeleteEmptyRowsSilent" 
REM   2. No dialogs, just console output
REM
REM To run this macro:
REM 1. Open your Excel file in LibreOffice Calc
REM 2. Tools -> Macros -> Organize Macros -> LibreOffice Basic
REM 3. Click "New" to create a new module
REM 4. Replace the default code with this entire macro
REM 5. Click the "Run" button or press F5
REM 6. Choose DeleteEmptyRows or DeleteEmptyRowsSilent
REM 7. Save your file when complete (File -> Save or Ctrl+S)
