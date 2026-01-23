"""
Comprehensive tests for process_file endpoint and related functions
These tests ensure full coverage before refactoring
"""
import pytest
import os
import json
from main import (
    generate_libreoffice_macro,
    generate_instructions,
    column_to_index,
    is_empty_or_zero
)


class TestProcessFileEndpoint:
    """Tests for the /api/process/<file_id> endpoint"""
    
    def test_process_file_without_filter_rules(self, client, auth_token, test_user, db_connection, sample_excel_file):
        """Test that process_file requires filter_rules"""
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        # Upload a file first
        with open(sample_excel_file, 'rb') as f:
            upload_response = client.post(
                '/api/upload',
                data={'file': (f, 'test_file.xlsx')},
                headers={'Authorization': f'Bearer {auth_token}'},
                content_type='multipart/form-data'
            )
        
        # Upload returns 201 for new files, 200 for duplicates
        assert upload_response.status_code in [200, 201], f"Upload failed: {upload_response.get_json()}"
        file_id = upload_response.get_json()['file_id']
        
        # Try to process without filter_rules
        response = client.post(
            f'/api/process/{file_id}',
            json={},
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        
        assert response.status_code == 400
        assert 'filter_rules' in response.get_json()['error'].lower()
    
    def test_process_file_with_empty_filter_rules(self, client, auth_token, sample_excel_file):
        """Test that process_file requires non-empty filter_rules"""
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        # Upload a file first
        with open(sample_excel_file, 'rb') as f:
            upload_response = client.post(
                '/api/upload',
                data={'file': (f, 'test_file.xlsx')},
                headers={'Authorization': f'Bearer {auth_token}'},
                content_type='multipart/form-data'
            )
        
        # Upload returns 201 for new files, 200 for duplicates
        assert upload_response.status_code in [200, 201], f"Upload failed: {upload_response.get_json()}"
        file_id = upload_response.get_json()['file_id']
        
        # Try to process with empty filter_rules
        response = client.post(
            f'/api/process/{file_id}',
            json={'filter_rules': []},
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        
        assert response.status_code == 400
    
    def test_process_file_identifies_rows_to_delete(self, client, auth_token, comprehensive_test_excel, test_user, db_connection):
        """Test that process_file correctly identifies rows to delete"""
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        # Upload the comprehensive test file
        with open(comprehensive_test_excel, 'rb') as f:
            upload_response = client.post(
                '/api/upload',
                data={'file': (f, 'comprehensive_test.xlsx')},
                headers={'Authorization': f'Bearer {auth_token}'},
                content_type='multipart/form-data'
            )
        
        # Upload returns 201 for new files, 200 for duplicates
        assert upload_response.status_code in [200, 201], f"Upload failed: {upload_response.get_json()}"
        file_id = upload_response.get_json()['file_id']
        
        # Process with default filter rules (F, G, H, I = 0)
        filter_rules = [
            {'column': 'F', 'value': '0'},
            {'column': 'G', 'value': '0'},
            {'column': 'H', 'value': '0'},
            {'column': 'I', 'value': '0'}
        ]
        
        response = client.post(
            f'/api/process/{file_id}',
            json={'filter_rules': filter_rules},
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Should find rows to delete
        assert 'total_rows_to_delete' in data
        assert data['total_rows_to_delete'] > 0
        assert 'sheets_affected' in data
        assert 'TestSheet1' in data['sheets_affected']
        assert 'downloads' in data
        assert 'macro' in data['downloads']
        assert 'instructions' in data['downloads']
    
    def test_process_file_no_rows_to_delete(self, client, auth_token, sample_excel_file):
        """Test process_file when no rows match filter criteria"""
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        # Upload a file
        with open(sample_excel_file, 'rb') as f:
            upload_response = client.post(
                '/api/upload',
                data={'file': (f, 'test_file.xlsx')},
                headers={'Authorization': f'Bearer {auth_token}'},
                content_type='multipart/form-data'
            )
        
        # Upload returns 201 for new files, 200 for duplicates
        assert upload_response.status_code in [200, 201], f"Upload failed: {upload_response.get_json()}"
        file_id = upload_response.get_json()['file_id']
        
        # Process with filter rules that won't match (all columns = 999)
        filter_rules = [
            {'column': 'F', 'value': '999'},
            {'column': 'G', 'value': '999'}
        ]
        
        response = client.post(
            f'/api/process/{file_id}',
            json={'filter_rules': filter_rules},
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['total_rows_to_delete'] == 0
        assert 'No rows found for deletion' in data['message']
    
    def test_process_file_generates_macro_and_instructions(self, client, auth_token, comprehensive_test_excel, test_directories, db_connection):
        """Test that process_file generates macro and instructions files"""
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        # Upload file
        with open(comprehensive_test_excel, 'rb') as f:
            upload_response = client.post(
                '/api/upload',
                data={'file': (f, 'comprehensive_test.xlsx')},
                headers={'Authorization': f'Bearer {auth_token}'},
                content_type='multipart/form-data'
            )
        
        # Upload returns 201 for new files, 200 for duplicates
        assert upload_response.status_code in [200, 201], f"Upload failed: {upload_response.get_json()}"
        file_id = upload_response.get_json()['file_id']
        
        # Process file
        filter_rules = [
            {'column': 'F', 'value': '0'},
            {'column': 'G', 'value': '0'},
            {'column': 'H', 'value': '0'},
            {'column': 'I', 'value': '0'}
        ]
        
        response = client.post(
            f'/api/process/{file_id}',
            json={'filter_rules': filter_rules},
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Check that macro and instructions files were created
        # The response contains file_ids, we need to check the database for stored filenames
        macro_file_id = data['downloads']['macro']['file_id']
        instructions_file_id = data['downloads']['instructions']['file_id']
        
        # Use db_connection fixture instead of get_db
        macro_info = db_connection.execute('SELECT stored_filename FROM files WHERE id = ?', (macro_file_id,)).fetchone()
        instructions_info = db_connection.execute('SELECT stored_filename FROM files WHERE id = ?', (instructions_file_id,)).fetchone()
        
        assert macro_info is not None
        assert instructions_info is not None
        
        macro_path = os.path.join(test_directories['macros'], macro_info['stored_filename'])
        instructions_path = os.path.join(test_directories['macros'], instructions_info['stored_filename'])
        
        assert os.path.exists(macro_path), f"Macro file not found: {macro_path}"
        assert os.path.exists(instructions_path), f"Instructions file not found: {instructions_path}"
        
        # Verify macro content
        with open(macro_path, 'r') as f:
            macro_content = f.read()
            assert 'Sub DeleteEmptyRows()' in macro_content
            assert 'TestSheet1' in macro_content or 'Sheet1' in macro_content
        
        # Verify instructions content
        with open(instructions_path, 'r') as f:
            instructions_content = f.read()
            assert 'EXCEL FILE CLEANUP INSTRUCTIONS' in instructions_content
            assert 'comprehensive_test.xlsx' in instructions_content


class TestGenerateLibreOfficeMacro:
    """Tests for generate_libreoffice_macro function"""
    
    def test_generate_macro_basic(self):
        """Test basic macro generation"""
        rows_to_delete_by_sheet = {
            'Sheet1': [2, 3, 5]
        }
        filter_rules = [
            {'column': 'F', 'value': '0'},
            {'column': 'G', 'value': '0'}
        ]
        
        macro = generate_libreoffice_macro(
            'test.xlsx',
            rows_to_delete_by_sheet,
            filter_rules
        )
        
        assert 'Sub DeleteEmptyRows()' in macro
        assert 'test.xlsx' in macro
        assert 'Sheet1' in macro
        assert 'removeByIndex' in macro
    
    def test_generate_macro_multiple_sheets(self):
        """Test macro generation with multiple sheets"""
        rows_to_delete_by_sheet = {
            'Sheet1': [2, 3],
            'Sheet2': [5, 6, 7]
        }
        
        macro = generate_libreoffice_macro(
            'test.xlsx',
            rows_to_delete_by_sheet,
            []
        )
        
        assert 'Sheet1' in macro
        assert 'Sheet2' in macro
        assert macro.count('hasByName') == 2  # One for each sheet
    
    def test_generate_macro_consecutive_rows(self):
        """Test that macro groups consecutive rows efficiently"""
        rows_to_delete_by_sheet = {
            'Sheet1': [5, 4, 3, 2]  # Consecutive rows
        }
        
        macro = generate_libreoffice_macro(
            'test.xlsx',
            rows_to_delete_by_sheet,
            []
        )
        
        # Should group consecutive rows into one removeByIndex call
        assert 'removeByIndex(1, 4)' in macro or 'removeByIndex(2, 4)' in macro
    
    def test_generate_macro_non_consecutive_rows(self):
        """Test macro with non-consecutive rows"""
        rows_to_delete_by_sheet = {
            'Sheet1': [2, 5, 10]  # Non-consecutive
        }
        
        macro = generate_libreoffice_macro(
            'test.xlsx',
            rows_to_delete_by_sheet,
            []
        )
        
        # Should have multiple removeByIndex calls
        assert macro.count('removeByIndex') >= 3


class TestGenerateInstructions:
    """Tests for generate_instructions function"""
    
    def test_generate_instructions_basic(self):
        """Test basic instructions generation"""
        instructions = generate_instructions(
            'test.xlsx',
            5,
            ['Sheet1'],
            [{'column': 'F', 'value': '0'}]
        )
        
        assert 'EXCEL FILE CLEANUP INSTRUCTIONS' in instructions
        assert 'test.xlsx' in instructions
        assert '5 rows' in instructions or '5' in instructions
        assert 'Sheet1' in instructions
        assert 'Column F' in instructions
    
    def test_generate_instructions_multiple_sheets(self):
        """Test instructions with multiple sheets"""
        instructions = generate_instructions(
            'test.xlsx',
            10,
            ['Sheet1', 'Sheet2'],
            [{'column': 'F', 'value': '0'}, {'column': 'G', 'value': '0'}]
        )
        
        assert 'Sheet1' in instructions
        assert 'Sheet2' in instructions
        assert 'Column F' in instructions
        assert 'Column G' in instructions
    
    def test_generate_instructions_with_exact_value_filter(self):
        """Test instructions with exact value filter (not zero)"""
        instructions = generate_instructions(
            'test.xlsx',
            3,
            ['Sheet1'],
            [{'column': 'A', 'value': 'DELETE'}]
        )
        
        assert "Column A equals 'DELETE'" in instructions
        assert 'empty or zero' not in instructions or instructions.count('empty or zero') == 1  # Only for zero filters


class TestProcessingLogic:
    """Tests for the core processing logic"""
    
    def test_row_identification_with_zeros(self, comprehensive_test_excel):
        """Test that rows with zeros are correctly identified"""
        from openpyxl import load_workbook
        from main import is_empty_or_zero, column_to_index
        
        wb = load_workbook(comprehensive_test_excel, data_only=True)
        sheet = wb['TestSheet1']
        
        filter_rules = [
            {'column': 'F', 'value': '0'},
            {'column': 'G', 'value': '0'},
            {'column': 'H', 'value': '0'},
            {'column': 'I', 'value': '0'}
        ]
        
        rows_to_delete = []
        for row_num in range(2, sheet.max_row + 1):  # Skip header
            all_match = True
            for rule in filter_rules:
                col_index = column_to_index(rule['column'])
                cell_val = sheet.cell(row=row_num, column=col_index).value
                
                if rule['value'] == '0':
                    if not is_empty_or_zero(cell_val):
                        all_match = False
                        break
            
            if all_match:
                rows_to_delete.append(row_num)
        
        # Should identify rows 2, 3, 4, 6, 7, 8, 10 (rows with all zeros in F,G,H,I)
        # Row 5 has values, Row 9 has partial match
        assert len(rows_to_delete) > 0
        assert 2 in rows_to_delete  # All zeros
        assert 5 not in rows_to_delete  # Has values
        assert 9 not in rows_to_delete  # Partial match
    
    def test_row_identification_with_exact_value(self, comprehensive_test_excel):
        """Test that rows with exact values are correctly identified"""
        from openpyxl import load_workbook
        from main import column_to_index
        
        wb = load_workbook(comprehensive_test_excel, data_only=True)
        sheet = wb['TestSheet1']
        
        filter_rules = [
            {'column': 'A', 'value': 'Row5_HasValues'}
        ]
        
        rows_to_delete = []
        for row_num in range(2, sheet.max_row + 1):
            all_match = True
            for rule in filter_rules:
                col_index = column_to_index(rule['column'])
                cell_val = sheet.cell(row=row_num, column=col_index).value
                
                if cell_val != rule['value']:
                    all_match = False
                    break
            
            if all_match:
                rows_to_delete.append(row_num)
        
        # Should only find row 5
        assert len(rows_to_delete) == 1
        assert 5 in rows_to_delete
