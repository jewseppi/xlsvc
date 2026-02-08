import os
from datetime import datetime, timedelta
from db import get_db
from file_utils import get_file_path


def cleanup_old_files():
    """
    Cleanup expired files - deletes all files (original and generated) older than 24 hours.
    When an original file is deleted, all related files (processed, macros, instructions, reports)
    and processing jobs are also deleted (cascade deletion).
    """
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        cutoff_iso = cutoff.isoformat()
        conn = get_db()
        deleted_count = 0

        # Step 1: Find and delete old original files with cascade deletion
        old_originals = conn.execute(
            '''SELECT id, stored_filename FROM files
               WHERE upload_date < ?
               AND (file_type = 'original' OR file_type IS NULL)''',
            (cutoff_iso,)
        ).fetchall()

        for original in old_originals:
            original_dict = dict(original)
            original_id = original_dict['id']
            
            # Find all related files (processed, macros, instructions, reports)
            related_files = conn.execute(
                '''SELECT id, stored_filename, file_type FROM files
                   WHERE parent_file_id = ?''',
                (original_id,)
            ).fetchall()
            
            # Delete all related files first
            for related_file in related_files:
                related_dict = dict(related_file)
                file_path = get_file_path(related_dict['file_type'], related_dict['stored_filename'])
                
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Warning: Could not delete file {file_path}: {e}")
                
                # Delete related processing jobs
                if related_dict['file_type'] == 'processed':
                    conn.execute('DELETE FROM processing_jobs WHERE result_file_id = ?', (related_dict['id'],))
                    conn.execute('DELETE FROM processing_jobs WHERE original_file_id = ? AND result_file_id IS NULL', (original_id,))
                
                # Delete file record
                conn.execute('DELETE FROM files WHERE id = ?', (related_dict['id'],))
                deleted_count += 1
            
            # Delete original file from disk
            original_path = get_file_path('original', original_dict['stored_filename'])
            if os.path.exists(original_path):
                try:
                    os.remove(original_path)
                except Exception as e:
                    print(f"Warning: Could not delete original file {original_path}: {e}")
            
            # Delete any remaining processing jobs for this original file
            conn.execute('DELETE FROM processing_jobs WHERE original_file_id = ?', (original_id,))
            
            # Delete original file record
            conn.execute('DELETE FROM files WHERE id = ?', (original_id,))
            deleted_count += 1

        # Step 2: Delete orphaned generated files (where original was already deleted)
        orphaned_files = conn.execute(
            '''SELECT id, stored_filename, file_type FROM files
               WHERE upload_date < ?
               AND file_type IN ('processed', 'macro', 'instructions', 'report')
               AND (parent_file_id IS NULL OR parent_file_id NOT IN (SELECT id FROM files))''',
            (cutoff_iso,)
        ).fetchall()

        for orphaned in orphaned_files:
            orphaned_dict = dict(orphaned)
            file_path = get_file_path(orphaned_dict['file_type'], orphaned_dict['stored_filename'])
            
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Warning: Could not delete orphaned file {file_path}: {e}")
            
            # Delete related processing jobs
            if orphaned_dict['file_type'] == 'processed':
                conn.execute('DELETE FROM processing_jobs WHERE result_file_id = ?', (orphaned_dict['id'],))
            
            # Delete file record
            conn.execute('DELETE FROM files WHERE id = ?', (orphaned_dict['id'],))
            deleted_count += 1

        # Step 3: Delete old processing_jobs records (completed/failed) older than 24 hours
        old_jobs = conn.execute(
            '''DELETE FROM processing_jobs
               WHERE (status = 'completed' OR status = 'failed')
               AND created_at < ?''',
            (cutoff_iso,)
        )
        jobs_deleted = old_jobs.rowcount
        if jobs_deleted > 0:
            deleted_count += jobs_deleted
            print(f"CLEANUP: Deleted {jobs_deleted} old processing job records")

        if deleted_count > 0:
            conn.commit()
            print(f"CLEANUP: Deleted {deleted_count} files and job records older than 24 hours")
        else:
            print("CLEANUP: No expired files found")

        conn.close()

    except Exception as e:
        print(f"CLEANUP ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
