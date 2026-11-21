//! Pure, bounded correction-session state for one durable recognition result.
//!
//! This module keeps editable text and IME preedit separate from the immutable
//! projection. It has no provider, file, window, or capture side effects.

use std::{collections::VecDeque, ops::Range};

use unicode_segmentation::UnicodeSegmentation;

use crate::journal::{
    JournalError, JournalReplayState, LOCAL_SENOCR_RASTER_PROVIDER_ID, MAX_REGION_CORRECTIONS,
    RecognitionCandidateV1, RecognitionProjectionV1, RegionCorrectionActionV1, RegionCorrectionV1,
    StoredRecognitionProjection, validate_region_correction_fields,
    validate_region_correction_text,
};

const MAX_CORRECTION_UNDO_STEPS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DraftKind {
    SetText,
    Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DraftMode {
    kind: Option<DraftKind>,
    candidate_rank: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EditorSnapshot {
    text: String,
    cursor_grapheme: usize,
    selection_graphemes: Option<Range<usize>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImePreedit {
    replacement_graphemes: Range<usize>,
    text: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CorrectionTextEditor {
    text: String,
    cursor_grapheme: usize,
    selection_graphemes: Option<Range<usize>>,
    undo: VecDeque<EditorSnapshot>,
    redo: VecDeque<EditorSnapshot>,
    preedit: Option<ImePreedit>,
}

impl CorrectionTextEditor {
    pub(crate) fn new(text: &str) -> Result<Self, JournalError> {
        validate_region_correction_text(text)?;
        Ok(Self {
            text: text.to_owned(),
            cursor_grapheme: text.graphemes(true).count(),
            selection_graphemes: None,
            undo: VecDeque::new(),
            redo: VecDeque::new(),
            preedit: None,
        })
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn grapheme_count(&self) -> usize {
        self.text.graphemes(true).count()
    }

    pub(crate) fn cursor_grapheme(&self) -> usize {
        self.cursor_grapheme
    }

    pub(crate) fn selection_graphemes(&self) -> Option<Range<usize>> {
        self.selection_graphemes.clone()
    }

    pub(crate) fn selected_text(&self) -> Option<&str> {
        let range = self.selection_graphemes.as_ref()?;
        let start = byte_offset_for_grapheme(&self.text, range.start);
        let end = byte_offset_for_grapheme(&self.text, range.end);
        Some(&self.text[start..end])
    }

    pub(crate) fn has_preedit(&self) -> bool {
        self.preedit.is_some()
    }

    pub(crate) fn undo_depth(&self) -> usize {
        self.undo.len()
    }

    fn clear_history(&mut self) {
        self.undo.clear();
        self.redo.clear();
        self.preedit = None;
    }

    pub(crate) fn set_cursor_grapheme(&mut self, cursor: usize) {
        self.cancel_preedit();
        self.cursor_grapheme = cursor.min(self.grapheme_count());
        self.selection_graphemes = None;
    }

    pub(crate) fn select_graphemes(&mut self, start: usize, end: usize) {
        self.cancel_preedit();
        let limit = self.grapheme_count();
        let start = start.min(limit);
        let end = end.min(limit);
        let range = start.min(end)..start.max(end);
        self.cursor_grapheme = range.end;
        self.selection_graphemes = (range.start != range.end).then_some(range);
    }

    pub(crate) fn select_all(&mut self) {
        self.cancel_preedit();
        let end = self.grapheme_count();
        self.cursor_grapheme = end;
        self.selection_graphemes = (end > 0).then_some(0..end);
    }

    pub(crate) fn move_cursor_left(&mut self) {
        self.cancel_preedit();
        if let Some(selection) = self.selection_graphemes.take() {
            self.cursor_grapheme = selection.start;
        } else {
            self.cursor_grapheme = self.cursor_grapheme.saturating_sub(1);
        }
    }

    pub(crate) fn move_cursor_right(&mut self) {
        self.cancel_preedit();
        if let Some(selection) = self.selection_graphemes.take() {
            self.cursor_grapheme = selection.end;
        } else {
            self.cursor_grapheme = (self.cursor_grapheme + 1).min(self.grapheme_count());
        }
    }

    pub(crate) fn move_cursor_up(&mut self, extend: bool) {
        self.move_cursor_vertical(-1, extend);
    }

    pub(crate) fn move_cursor_down(&mut self, extend: bool) {
        self.move_cursor_vertical(1, extend);
    }

    pub(crate) fn move_cursor_up_wrapped(&mut self, columns: usize, extend: bool) {
        self.move_cursor_vertical_wrapped(-1, columns, extend);
    }

    pub(crate) fn move_cursor_down_wrapped(&mut self, columns: usize, extend: bool) {
        self.move_cursor_vertical_wrapped(1, columns, extend);
    }

    pub(crate) fn move_cursor_on_visual_rows(
        &mut self,
        visual_rows: &[Range<usize>],
        delta: isize,
        extend: bool,
    ) {
        if visual_rows.is_empty() {
            return;
        }
        self.cancel_preedit();
        self.move_cursor_to_vertical_line(visual_rows, delta, extend);
    }

    pub(crate) fn visual_line_ranges(&self, columns: usize) -> Vec<Range<usize>> {
        grapheme_visual_line_ranges(&self.text, columns)
    }

    pub(crate) fn move_to_line_start(&mut self, extend: bool) {
        self.move_to_line_edge(false, extend);
    }

    pub(crate) fn move_to_line_end(&mut self, extend: bool) {
        self.move_to_line_edge(true, extend);
    }

    fn move_cursor_vertical(&mut self, delta: isize, extend: bool) {
        self.cancel_preedit();
        let lines = grapheme_line_ranges(&self.text);
        self.move_cursor_to_vertical_line(&lines, delta, extend);
    }

    fn move_cursor_vertical_wrapped(&mut self, delta: isize, columns: usize, extend: bool) {
        self.cancel_preedit();
        let lines = grapheme_visual_line_ranges(&self.text, columns);
        self.move_cursor_to_vertical_line(&lines, delta, extend);
    }

    fn move_cursor_to_vertical_line(&mut self, lines: &[Range<usize>], delta: isize, extend: bool) {
        let current_line = lines
            .iter()
            .position(|range| self.cursor_grapheme >= range.start && self.cursor_grapheme <= range.end)
            .unwrap_or_else(|| lines.len().saturating_sub(1));
        let current = isize::try_from(current_line).unwrap_or(isize::MAX);
        let target = usize::try_from(
            current
                .saturating_add(delta)
                .clamp(0, isize::try_from(lines.len().saturating_sub(1)).unwrap_or(isize::MAX)),
        )
        .unwrap_or_default();
        let current_range = &lines[current_line];
        let column = self.cursor_grapheme.saturating_sub(current_range.start);
        let target_range = &lines[target];
        let cursor = target_range
            .start
            .saturating_add(column.min(target_range.end.saturating_sub(target_range.start)));
        self.move_cursor_to(cursor, extend);
    }

    fn move_to_line_edge(&mut self, end: bool, extend: bool) {
        self.cancel_preedit();
        let lines = grapheme_line_ranges(&self.text);
        let range = lines
            .iter()
            .find(|range| self.cursor_grapheme >= range.start && self.cursor_grapheme <= range.end)
            .unwrap_or_else(|| lines.last().expect("empty text has one grapheme line"));
        self.move_cursor_to(if end { range.end } else { range.start }, extend);
    }

    fn move_cursor_to(&mut self, cursor: usize, extend: bool) {
        let cursor = cursor.min(self.grapheme_count());
        if !extend {
            self.cursor_grapheme = cursor;
            self.selection_graphemes = None;
            return;
        }
        let anchor = self.selection_graphemes.as_ref().map_or(self.cursor_grapheme, |range| {
            if self.cursor_grapheme == range.start {
                range.end
            } else {
                range.start
            }
        });
        self.cursor_grapheme = cursor;
        self.selection_graphemes = (anchor != cursor).then_some(anchor.min(cursor)..anchor.max(cursor));
    }

    pub(crate) fn move_cursor_left_extending_selection(&mut self) {
        self.move_cursor_extending_selection(false);
    }

    pub(crate) fn move_cursor_right_extending_selection(&mut self) {
        self.move_cursor_extending_selection(true);
    }

    fn move_cursor_extending_selection(&mut self, right: bool) {
        self.cancel_preedit();
        let anchor = self.selection_graphemes.as_ref().map_or(self.cursor_grapheme, |range| {
            if self.cursor_grapheme == range.start {
                range.end
            } else {
                range.start
            }
        });
        let cursor = if right {
            (self.cursor_grapheme + 1).min(self.grapheme_count())
        } else {
            self.cursor_grapheme.saturating_sub(1)
        };
        self.cursor_grapheme = cursor;
        self.selection_graphemes = (anchor != cursor).then_some(anchor.min(cursor)..anchor.max(cursor));
    }

    pub(crate) fn set_text(&mut self, text: &str) -> Result<bool, JournalError> {
        self.cancel_preedit();
        let count = self.grapheme_count();
        self.replace_grapheme_range(0..count, text)
    }

    pub(crate) fn insert_text(&mut self, text: &str) -> Result<bool, JournalError> {
        self.cancel_preedit();
        let range = self
            .selection_graphemes
            .clone()
            .unwrap_or(self.cursor_grapheme..self.cursor_grapheme);
        self.replace_grapheme_range(range, text)
    }

    pub(crate) fn insert_newline(&mut self) -> Result<bool, JournalError> {
        self.insert_text("\n")
    }

    pub(crate) fn delete_backward(&mut self) -> Result<bool, JournalError> {
        self.cancel_preedit();
        let range = if let Some(selection) = self.selection_graphemes.clone() {
            selection
        } else if self.cursor_grapheme > 0 {
            self.cursor_grapheme - 1..self.cursor_grapheme
        } else {
            return Ok(false);
        };
        self.replace_grapheme_range(range, "")
    }

    pub(crate) fn delete_forward(&mut self) -> Result<bool, JournalError> {
        self.cancel_preedit();
        let range = if let Some(selection) = self.selection_graphemes.clone() {
            selection
        } else if self.cursor_grapheme < self.grapheme_count() {
            self.cursor_grapheme..self.cursor_grapheme + 1
        } else {
            return Ok(false);
        };
        self.replace_grapheme_range(range, "")
    }

    pub(crate) fn begin_preedit(&mut self) {
        if self.preedit.is_none() {
            let replacement_graphemes = self
                .selection_graphemes
                .clone()
                .unwrap_or(self.cursor_grapheme..self.cursor_grapheme);
            self.preedit = Some(ImePreedit {
                replacement_graphemes,
                text: String::new(),
            });
        }
    }

    pub(crate) fn update_preedit(&mut self, text: &str) -> Result<(), JournalError> {
        self.begin_preedit();
        let Some(replacement) = self
            .preedit
            .as_ref()
            .map(|preedit| preedit.replacement_graphemes.clone())
        else {
            return Ok(());
        };
        self.replaced_text(replacement, text)?;
        if let Some(preedit) = &mut self.preedit {
            preedit.text.clear();
            preedit.text.push_str(text);
        }
        Ok(())
    }

    /// Returns a display-only composition. The committed `text()` is unchanged
    /// until `commit_preedit` succeeds.
    pub(crate) fn preview_text(&self) -> Result<String, JournalError> {
        match &self.preedit {
            Some(preedit) => {
                self.replaced_text(preedit.replacement_graphemes.clone(), &preedit.text)
            }
            None => Ok(self.text.clone()),
        }
    }

    pub(crate) fn commit_preedit(&mut self) -> Result<bool, JournalError> {
        let Some(preedit) = self.preedit.take() else {
            return Ok(false);
        };
        match self.replace_grapheme_range(preedit.replacement_graphemes.clone(), &preedit.text) {
            Ok(changed) => Ok(changed),
            Err(error) => {
                self.preedit = Some(preedit);
                Err(error)
            }
        }
    }

    /// Commits the text supplied by Winit's authoritative Ime::Commit event.
    /// The preedit's replacement range is used, but its display text is never
    /// committed a second time.
    pub(crate) fn commit_ime_text(&mut self, text: &str) -> Result<bool, JournalError> {
        let replacement = self.preedit.take().map(|preedit| preedit.replacement_graphemes);
        let range = replacement.unwrap_or_else(|| {
            self.selection_graphemes
                .clone()
                .unwrap_or(self.cursor_grapheme..self.cursor_grapheme)
        });
        self.replace_grapheme_range(range, text)
    }

    pub(crate) fn cancel_preedit(&mut self) -> bool {
        self.preedit.take().is_some()
    }

    pub(crate) fn undo(&mut self) -> bool {
        if self.cancel_preedit() {
            return true;
        }
        let Some(snapshot) = self.undo.pop_back() else {
            return false;
        };
        let current = self.snapshot();
        push_bounded(&mut self.redo, current);
        self.restore(snapshot);
        true
    }

    pub(crate) fn redo(&mut self) -> bool {
        if self.preedit.is_some() {
            return false;
        }
        let Some(snapshot) = self.redo.pop_back() else {
            return false;
        };
        let current = self.snapshot();
        push_bounded(&mut self.undo, current);
        self.restore(snapshot);
        true
    }

    fn replace_grapheme_range(
        &mut self,
        range: Range<usize>,
        replacement: &str,
    ) -> Result<bool, JournalError> {
        let grapheme_count = self.grapheme_count();
        let start = range.start.min(grapheme_count);
        let end = range.end.min(grapheme_count);
        let range = start.min(end)..start.max(end);
        let start_byte = byte_offset_for_grapheme(&self.text, range.start);
        let next_text = self.replaced_text(range, replacement)?;
        let insertion_end_byte = start_byte.saturating_add(replacement.len());
        let changed = next_text != self.text;
        if changed {
            self.record_undo_boundary();
            self.text = next_text;
        }
        self.cursor_grapheme = cursor_at_or_after_byte(&self.text, insertion_end_byte);
        self.selection_graphemes = None;
        self.preedit = None;
        Ok(changed)
    }

    fn replaced_text(
        &self,
        range: Range<usize>,
        replacement: &str,
    ) -> Result<String, JournalError> {
        let grapheme_count = self.grapheme_count();
        let start = range.start.min(grapheme_count);
        let end = range.end.min(grapheme_count);
        let range = start.min(end)..start.max(end);
        let start_byte = byte_offset_for_grapheme(&self.text, range.start);
        let end_byte = byte_offset_for_grapheme(&self.text, range.end);
        let next_len = self
            .text
            .len()
            .saturating_sub(end_byte - start_byte)
            .saturating_add(replacement.len());
        crate::journal::validate_region_correction_text_length(next_len)?;
        let mut next_text = String::with_capacity(next_len);
        next_text.push_str(&self.text[..start_byte]);
        next_text.push_str(replacement);
        next_text.push_str(&self.text[end_byte..]);
        validate_region_correction_text(&next_text)?;
        Ok(next_text)
    }

    fn record_undo_boundary(&mut self) {
        let snapshot = self.snapshot();
        push_bounded(&mut self.undo, snapshot);
        self.redo.clear();
    }

    fn snapshot(&self) -> EditorSnapshot {
        EditorSnapshot {
            text: self.text.clone(),
            cursor_grapheme: self.cursor_grapheme,
            selection_graphemes: self.selection_graphemes.clone(),
        }
    }

    fn restore(&mut self, snapshot: EditorSnapshot) {
        self.text = snapshot.text;
        self.cursor_grapheme = snapshot.cursor_grapheme.min(self.grapheme_count());
        self.selection_graphemes = snapshot.selection_graphemes;
        self.preedit = None;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CorrectionSessionError {
    ProjectionNotFound,
    ProjectionProjectMismatch,
    CandidateSelectionUnsupported,
    PersistedTextInvalid,
    HistoryLimitExceeded,
    HistoryAllocationFailed,
    AcknowledgementDoesNotMatchDraft,
}

/// Minimal owned display history for one projection. The immutable projection
/// binding is stored once on the session, not copied into every history row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CorrectionHistoryEntry {
    pub correction_id: String,
    pub action: RegionCorrectionActionV1,
}

#[derive(Debug)]
pub(crate) struct CorrectionSession {
    stored_projection: StoredRecognitionProjection,
    correction_history: Vec<CorrectionHistoryEntry>,
    editor: CorrectionTextEditor,
    draft_kind: Option<DraftKind>,
    selected_candidate_rank: Option<u16>,
    cancelled: bool,
    undo_modes: VecDeque<DraftMode>,
    redo_modes: VecDeque<DraftMode>,
}

impl CorrectionSession {
    /// Opens a newly persisted projection received through its durable writer
    /// acknowledgement. New projections have no correction history yet.
    pub(crate) fn from_durable_projection(
        stored_projection: StoredRecognitionProjection,
    ) -> Result<Self, CorrectionSessionError> {
        let editor = CorrectionTextEditor::new("")
            .map_err(|_| CorrectionSessionError::PersistedTextInvalid)?;
        Ok(Self {
            stored_projection,
            correction_history: Vec::new(),
            editor,
            draft_kind: None,
            selected_candidate_rank: None,
            cancelled: false,
            undo_modes: VecDeque::new(),
            redo_modes: VecDeque::new(),
        })
    }

    pub(crate) fn open(
        state: &JournalReplayState,
        projection_id: &str,
    ) -> Result<Self, CorrectionSessionError> {
        let stored_projection = state
            .recognition_projections
            .iter()
            .find(|stored| stored.projection.projection_id == projection_id)
            .cloned()
            .ok_or(CorrectionSessionError::ProjectionNotFound)?;
        if stored_projection.projection.ink.journal_id != state.journal_id {
            return Err(CorrectionSessionError::ProjectionProjectMismatch);
        }
        let mut correction_history = Vec::new();
        for stored in state
            .region_corrections
            .iter()
            .filter(|stored| stored.correction.projection_id == projection_id)
        {
            if correction_history.len() >= MAX_REGION_CORRECTIONS {
                return Err(CorrectionSessionError::HistoryLimitExceeded);
            }
            correction_history
                .try_reserve(1)
                .map_err(|_| CorrectionSessionError::HistoryAllocationFailed)?;
            correction_history.push(CorrectionHistoryEntry {
                correction_id: stored.correction.correction_id.clone(),
                action: stored.correction.action.clone(),
            });
        }
        let latest_action = correction_history.last().map(|entry| &entry.action);
        let (initial_text, draft_kind) = match latest_action {
            Some(RegionCorrectionActionV1::SetText(text)) => {
                (text.as_str(), Some(DraftKind::SetText))
            }
            Some(RegionCorrectionActionV1::Reset) => ("", Some(DraftKind::Reset)),
            None => ("", None),
        };
        let editor = CorrectionTextEditor::new(initial_text)
            .map_err(|_| CorrectionSessionError::PersistedTextInvalid)?;
        Ok(Self {
            stored_projection,
            correction_history,
            editor,
            draft_kind,
            selected_candidate_rank: None,
            cancelled: false,
            undo_modes: VecDeque::new(),
            redo_modes: VecDeque::new(),
        })
    }

    pub(crate) fn projection(&self) -> &RecognitionProjectionV1 {
        &self.stored_projection.projection
    }

    pub(crate) fn projection_id(&self) -> &str {
        &self.stored_projection.projection.projection_id
    }

    pub(crate) fn candidates(&self) -> &[RecognitionCandidateV1] {
        &self.stored_projection.projection.candidates
    }

    pub(crate) fn correction_history(&self) -> &[CorrectionHistoryEntry] {
        &self.correction_history
    }

    pub(crate) fn latest_saved_action(&self) -> Option<&RegionCorrectionActionV1> {
        self.correction_history.last().map(|entry| &entry.action)
    }

    /// Text to display while this session is open. An explicit empty SetText
    /// stays blank; Reset and no correction display the immutable rank-zero
    /// provider result when one is available. Cancel restores the last saved
    /// correction or that same provider base without discarding the copyable
    /// unsaved draft buffer.
    pub(crate) fn effective_text(&self) -> Option<&str> {
        if self.cancelled {
            return match self.latest_saved_action() {
                Some(RegionCorrectionActionV1::SetText(text)) => Some(text),
                Some(RegionCorrectionActionV1::Reset) | None => self.base_provider_text(),
            };
        }
        match self.draft_kind {
            Some(DraftKind::SetText) => Some(self.editor.text()),
            Some(DraftKind::Reset) => self.base_provider_text(),
            None => match self.latest_saved_action() {
                Some(RegionCorrectionActionV1::SetText(text)) => Some(text),
                Some(RegionCorrectionActionV1::Reset) | None => self.base_provider_text(),
            },
        }
    }

    pub(crate) fn text(&self) -> &str {
        self.editor.text()
    }

    pub(crate) fn editor(&self) -> &CorrectionTextEditor {
        &self.editor
    }

    pub(crate) fn selected_text(&self) -> Option<&str> {
        self.editor.selected_text()
    }

    pub(crate) fn selected_candidate_rank(&self) -> Option<u16> {
        self.selected_candidate_rank
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    pub(crate) fn is_dirty(&self) -> bool {
        !self.cancelled && self.draft_action().as_ref() != self.latest_saved_action()
    }

    pub(crate) fn draft_action(&self) -> Option<RegionCorrectionActionV1> {
        match self.draft_kind? {
            DraftKind::SetText => Some(RegionCorrectionActionV1::SetText(
                self.editor.text().to_owned(),
            )),
            DraftKind::Reset => Some(RegionCorrectionActionV1::Reset),
        }
    }

    fn base_provider_text(&self) -> Option<&str> {
        self.projection()
            .candidates
            .iter()
            .find(|candidate| candidate.rank == 0)
            .map(|candidate| candidate.recognized_text.as_str())
    }

    pub(crate) fn select_candidate_rank(
        &mut self,
        rank: u16,
    ) -> Result<(), CorrectionSessionError> {
        let projection = self.projection();
        if projection.provider.provider_id != LOCAL_SENOCR_RASTER_PROVIDER_ID
            || projection.candidates.len() != 1
            || rank != 0
            || projection.candidates[0].rank != 0
        {
            return Err(CorrectionSessionError::CandidateSelectionUnsupported);
        }
        let candidate = &projection.candidates[0];
        let text = candidate.recognized_text.clone();
        self.set_draft_text(&text, Some(rank))
            .map_err(|_| CorrectionSessionError::PersistedTextInvalid)
    }

    pub(crate) fn set_text(&mut self, text: &str) -> Result<(), JournalError> {
        self.set_draft_text(text, None)
    }

    fn set_draft_text(
        &mut self,
        text: &str,
        candidate_rank: Option<u16>,
    ) -> Result<(), JournalError> {
        let before_mode = self.mode();
        let after_mode = DraftMode {
            kind: Some(DraftKind::SetText),
            candidate_rank,
        };
        let same_text = self.editor.text() == text;
        if same_text && before_mode != after_mode {
            self.editor.record_undo_boundary();
        }
        let changed = self.editor.set_text(text)?;
        if changed || before_mode != after_mode {
            self.record_mode_undo(before_mode);
            self.draft_kind = after_mode.kind;
            self.selected_candidate_rank = after_mode.candidate_rank;
        }
        self.cancelled = false;
        Ok(())
    }

    pub(crate) fn reset(&mut self) -> Result<(), JournalError> {
        let before_mode = self.mode();
        let after_mode = DraftMode {
            kind: Some(DraftKind::Reset),
            candidate_rank: None,
        };
        if self.editor.text().is_empty() && before_mode != after_mode {
            self.editor.record_undo_boundary();
        }
        let changed = self.editor.set_text("")?;
        if changed || before_mode != after_mode {
            self.record_mode_undo(before_mode);
            self.draft_kind = after_mode.kind;
            self.selected_candidate_rank = None;
        }
        self.cancelled = false;
        Ok(())
    }

    pub(crate) fn insert_text(&mut self, text: &str) -> Result<bool, JournalError> {
        self.apply_text_edit(|editor| editor.insert_text(text))
    }

    pub(crate) fn insert_newline(&mut self) -> Result<bool, JournalError> {
        self.apply_text_edit(CorrectionTextEditor::insert_newline)
    }

    pub(crate) fn delete_backward(&mut self) -> Result<bool, JournalError> {
        self.apply_text_edit(CorrectionTextEditor::delete_backward)
    }

    pub(crate) fn delete_forward(&mut self) -> Result<bool, JournalError> {
        self.apply_text_edit(CorrectionTextEditor::delete_forward)
    }

    fn apply_text_edit(
        &mut self,
        edit: impl FnOnce(&mut CorrectionTextEditor) -> Result<bool, JournalError>,
    ) -> Result<bool, JournalError> {
        self.prepare_editor_for_edit()?;
        let before_mode = self.mode();
        let changed = edit(&mut self.editor)?;
        if changed {
            self.record_mode_undo(before_mode);
            self.draft_kind = Some(DraftKind::SetText);
            self.selected_candidate_rank = None;
            self.cancelled = false;
        }
        Ok(changed)
    }

    /// Seeds the editor from the effective saved/provider text without
    /// creating a correction draft. This lets the UI put the caret in the
    /// displayed base result while an untouched session remains a no-op.
    pub(crate) fn prepare_editor_for_edit(&mut self) -> Result<(), JournalError> {
        if self.cancelled {
            let saved_kind = match self.latest_saved_action() {
                Some(RegionCorrectionActionV1::SetText(_)) => Some(DraftKind::SetText),
                Some(RegionCorrectionActionV1::Reset) => Some(DraftKind::Reset),
                None => None,
            };
            let text = self.effective_text().unwrap_or_default().to_owned();
            self.editor = CorrectionTextEditor::new(&text)?;
            self.draft_kind = saved_kind;
            self.selected_candidate_rank = None;
            self.cancelled = false;
            return Ok(());
        }
        if !matches!(self.draft_kind, Some(DraftKind::SetText)) {
            let text = self.effective_text().unwrap_or_default().to_owned();
            if self.editor.text() != text {
                self.editor = CorrectionTextEditor::new(&text)?;
            }
        }
        Ok(())
    }

    pub(crate) fn set_cursor_grapheme(&mut self, cursor: usize) {
        self.editor.set_cursor_grapheme(cursor);
    }

    pub(crate) fn select_graphemes(&mut self, start: usize, end: usize) {
        self.editor.select_graphemes(start, end);
    }

    pub(crate) fn move_cursor_left(&mut self) {
        self.editor.move_cursor_left();
    }

    pub(crate) fn move_cursor_right(&mut self) {
        self.editor.move_cursor_right();
    }

    pub(crate) fn move_cursor_up(&mut self, extend: bool) {
        self.editor.move_cursor_up(extend);
    }

    pub(crate) fn move_cursor_down(&mut self, extend: bool) {
        self.editor.move_cursor_down(extend);
    }

    pub(crate) fn move_cursor_up_wrapped(&mut self, columns: usize, extend: bool) {
        self.editor.move_cursor_up_wrapped(columns, extend);
    }

    pub(crate) fn move_cursor_down_wrapped(&mut self, columns: usize, extend: bool) {
        self.editor.move_cursor_down_wrapped(columns, extend);
    }

    pub(crate) fn move_cursor_on_visual_rows(
        &mut self,
        visual_rows: &[Range<usize>],
        delta: isize,
        extend: bool,
    ) {
        self.editor
            .move_cursor_on_visual_rows(visual_rows, delta, extend);
    }

    pub(crate) fn move_to_line_start(&mut self, extend: bool) {
        self.editor.move_to_line_start(extend);
    }

    pub(crate) fn move_to_line_end(&mut self, extend: bool) {
        self.editor.move_to_line_end(extend);
    }

    pub(crate) fn move_cursor_left_extending_selection(&mut self) {
        self.editor.move_cursor_left_extending_selection();
    }

    pub(crate) fn move_cursor_right_extending_selection(&mut self) {
        self.editor.move_cursor_right_extending_selection();
    }

    pub(crate) fn select_all(&mut self) {
        self.editor.select_all();
    }

    pub(crate) fn update_ime_preedit(&mut self, text: &str) -> Result<(), JournalError> {
        self.editor.update_preedit(text)
    }

    pub(crate) fn ime_preview_text(&self) -> Result<String, JournalError> {
        self.editor.preview_text()
    }

    pub(crate) fn commit_ime_preedit(&mut self) -> Result<bool, JournalError> {
        self.apply_text_edit(CorrectionTextEditor::commit_preedit)
    }

    pub(crate) fn commit_ime_text(&mut self, text: &str) -> Result<bool, JournalError> {
        self.apply_text_edit(|editor| editor.commit_ime_text(text))
    }

    pub(crate) fn cancel_ime_preedit(&mut self) -> bool {
        self.editor.cancel_preedit()
    }

    /// Ordinary focus loss preserves committed draft text; the platform UI
    /// may discard only the transient IME composition when it loses focus.
    pub(crate) fn on_focus_lost(&mut self) {}

    pub(crate) fn undo(&mut self) -> bool {
        if self.editor.has_preedit() {
            return self.editor.undo();
        }
        if !self.editor.undo() {
            return false;
        }
        let current_mode = self.mode();
        self.redo_modes.push_back(current_mode);
        if let Some(previous) = self.undo_modes.pop_back() {
            self.restore_mode(previous);
        } else {
            self.draft_kind = Some(DraftKind::SetText);
            self.selected_candidate_rank = None;
        }
        true
    }

    pub(crate) fn redo(&mut self) -> bool {
        if self.editor.has_preedit() || !self.editor.redo() {
            return false;
        }
        let current_mode = self.mode();
        self.undo_modes.push_back(current_mode);
        if let Some(next) = self.redo_modes.pop_back() {
            self.restore_mode(next);
        } else {
            self.draft_kind = Some(DraftKind::SetText);
            self.selected_candidate_rank = None;
        }
        true
    }

    pub(crate) fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub(crate) fn build_correction(
        &self,
        correction_id: &str,
    ) -> Result<Option<RegionCorrectionV1>, JournalError> {
        if self.cancelled || !self.is_dirty() {
            return Ok(None);
        }
        let Some(action) = self.draft_action() else {
            return Ok(None);
        };
        let correction = RegionCorrectionV1 {
            correction_id: correction_id.to_owned(),
            projection_id: self.projection_id().to_owned(),
            ink: self.projection().ink.clone(),
            action,
        };
        validate_region_correction_fields(&correction)?;
        Ok(Some(correction))
    }

    pub(crate) fn acknowledge_committed(
        &mut self,
        correction: &RegionCorrectionV1,
    ) -> Result<(), CorrectionSessionError> {
        if correction.projection_id != self.projection_id()
            || correction.ink != self.projection().ink
            || self.draft_action().as_ref() != Some(&correction.action)
            || self
                .correction_history
                .iter()
                .any(|entry| entry.correction_id == correction.correction_id)
        {
            return Err(CorrectionSessionError::AcknowledgementDoesNotMatchDraft);
        }
        if self.correction_history.len() >= MAX_REGION_CORRECTIONS {
            return Err(CorrectionSessionError::HistoryLimitExceeded);
        }
        self.correction_history
            .try_reserve(1)
            .map_err(|_| CorrectionSessionError::HistoryAllocationFailed)?;
        self.correction_history.push(CorrectionHistoryEntry {
            correction_id: correction.correction_id.clone(),
            action: correction.action.clone(),
        });
        self.undo_modes.clear();
        self.redo_modes.clear();
        self.editor.clear_history();
        self.cancelled = false;
        Ok(())
    }

    fn mode(&self) -> DraftMode {
        DraftMode {
            kind: self.draft_kind,
            candidate_rank: self.selected_candidate_rank,
        }
    }

    fn restore_mode(&mut self, mode: DraftMode) {
        self.draft_kind = mode.kind;
        self.selected_candidate_rank = mode.candidate_rank;
    }

    fn record_mode_undo(&mut self, mode: DraftMode) {
        push_bounded(&mut self.undo_modes, mode);
        self.redo_modes.clear();
    }
}

fn byte_offset_for_grapheme(text: &str, grapheme: usize) -> usize {
    text.grapheme_indices(true)
        .nth(grapheme)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

fn cursor_at_or_after_byte(text: &str, byte: usize) -> usize {
    text.grapheme_indices(true)
        .enumerate()
        .find_map(|(index, (start, _))| (start >= byte).then_some(index))
        .unwrap_or_else(|| text.graphemes(true).count())
}

fn grapheme_line_ranges(text: &str) -> Vec<Range<usize>> {
    let graphemes = text.graphemes(true).collect::<Vec<_>>();
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, grapheme) in graphemes.iter().enumerate() {
        if matches!(*grapheme, "\n" | "\r\n" | "\r") {
            lines.push(start..index);
            start = index + 1;
        }
    }
    lines.push(start..graphemes.len());
    lines
}

fn grapheme_visual_line_ranges(text: &str, columns: usize) -> Vec<Range<usize>> {
    let columns = columns.max(1);
    let graphemes = text.graphemes(true).collect::<Vec<_>>();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut columns_used = 0;
    for (index, grapheme) in graphemes.iter().enumerate() {
        if matches!(*grapheme, "\n" | "\r\n" | "\r") {
            lines.push(start..index);
            start = index + 1;
            columns_used = 0;
            continue;
        }
        if columns_used >= columns {
            lines.push(start..index);
            start = index;
            columns_used = 0;
        }
        columns_used += 1;
    }
    lines.push(start..graphemes.len());
    lines
}

fn push_bounded<T>(queue: &mut VecDeque<T>, value: T) {
    if queue.len() >= MAX_CORRECTION_UNDO_STEPS {
        queue.pop_front();
    }
    queue.push_back(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{
        ProjectionInkBindingV1, ProjectionProviderProvenanceV1, ProjectionStrokeViewV1,
        RecognitionCandidateV1, RecognitionProjectionV1, StoredRecognitionProjection,
        StoredRegionCorrection, StrokeRef, StrokeViewFrame,
    };

    fn test_binding(journal_id: &str, region_id: &str) -> ProjectionInkBindingV1 {
        let stroke = StrokeRef {
            journal_id: journal_id.to_owned(),
            session_id: "session-1".to_owned(),
            source_api: "direct-wm-pointer-pen-history".to_owned(),
            device_id: Some("session-device-1".to_owned()),
            pointer_id: Some(1),
            stroke_id: "stroke-1".to_owned(),
        };
        ProjectionInkBindingV1 {
            journal_id: journal_id.to_owned(),
            logical_revision: 3,
            last_sequence: 7,
            region_id: region_id.to_owned(),
            line_id: Some("line-1".to_owned()),
            input_view_id: "input-view-v1-0000000000000001".to_owned(),
            ink_binding_sha256: "a".repeat(64),
            selected_strokes: vec![stroke.clone()],
            source_sample_sequences: vec![6],
            stroke_views: vec![ProjectionStrokeViewV1 {
                stroke,
                frame: StrokeViewFrame::default(),
            }],
        }
    }

    fn test_projection(
        projection_id: &str,
        journal_id: &str,
        region_id: &str,
        candidates: Vec<RecognitionCandidateV1>,
    ) -> RecognitionProjectionV1 {
        RecognitionProjectionV1 {
            projection_id: projection_id.to_owned(),
            ink: test_binding(journal_id, region_id),
            provider: ProjectionProviderProvenanceV1 {
                provider_id: "external-raster-provider".to_owned(),
                provider_version: "synthetic-version".to_owned(),
                model_version: None,
                resource_version: None,
                configuration_id: "operator-test-config".to_owned(),
                configuration_fingerprint: "provider-config-v1-fnv64-0000000000000001".to_owned(),
            },
            candidates,
            input_modalities: None,
            generated_raster: None,
        }
    }

    fn candidate(rank: u16, text: &str) -> RecognitionCandidateV1 {
        RecognitionCandidateV1 {
            rank,
            recognized_text: text.to_owned(),
            native_score_raw: None,
            stroke_ranges: Vec::new(),
        }
    }

    fn test_state(
        projections: Vec<RecognitionProjectionV1>,
        corrections: Vec<RegionCorrectionV1>,
    ) -> JournalReplayState {
        let journal_id = projections
            .first()
            .map(|projection| projection.ink.journal_id.clone())
            .unwrap_or_default();
        let mut state = JournalReplayState::default();
        state.journal_id = journal_id;
        state.recognition_projections = projections
            .into_iter()
            .enumerate()
            .map(|(index, projection)| StoredRecognitionProjection {
                sequence: 10 + index as u64,
                app_epoch_id: "session-1".to_owned(),
                app_arrival_elapsed_ns: index as u128,
                projection,
            })
            .collect();
        state.region_corrections = corrections
            .into_iter()
            .enumerate()
            .map(|(index, correction)| StoredRegionCorrection {
                sequence: 20 + index as u64,
                app_epoch_id: "session-1".to_owned(),
                app_arrival_elapsed_ns: index as u128,
                correction,
            })
            .collect();
        state
    }

    #[test]
    fn correction_session_selects_only_single_rank_zero_senocr_and_keeps_projection_immutable() {
        let mut projection = test_projection(
            "projection-rank-test",
            "journal-rank-test",
            "region-rank-test",
            vec![candidate(0, "rank zero")],
        );
        projection.provider.provider_id = LOCAL_SENOCR_RASTER_PROVIDER_ID.to_owned();
        let state = test_state(vec![projection.clone()], Vec::new());
        let before = state.recognition_projections[0].projection.clone();
        let mut session = CorrectionSession::open(&state, &projection.projection_id).unwrap();

        session.select_candidate_rank(0).unwrap();

        assert_eq!(session.selected_candidate_rank(), Some(0));
        assert_eq!(session.text(), "rank zero");
        let correction = session
            .build_correction("correction-rank-test")
            .unwrap()
            .unwrap();
        assert_eq!(
            correction.action,
            RegionCorrectionActionV1::SetText("rank zero".to_owned())
        );
        assert_eq!(correction.projection_id, projection.projection_id);
        assert_eq!(correction.ink, projection.ink);
        let serialized = serde_json::to_value(&correction).unwrap();
        assert!(serialized.get("rank").is_none());
        assert!(serialized.get("candidate_rank").is_none());
        assert_eq!(state.recognition_projections[0].projection, before);
        assert_eq!(state.region_corrections.len(), 0);

        let reopened_state = test_state(vec![projection.clone()], vec![correction.clone()]);
        let reopened = CorrectionSession::open(&reopened_state, &projection.projection_id).unwrap();
        assert_eq!(reopened.selected_candidate_rank(), None);
        assert_eq!(reopened.text(), "rank zero");
        assert_eq!(reopened.latest_saved_action(), Some(&correction.action));
    }

    #[test]
    fn correction_session_refuses_nonzero_non_senocr_or_multiple_candidate_selection() {
        let mut nonzero = test_projection(
            "projection-nonzero-rank",
            "journal-nonzero-rank",
            "region-nonzero-rank",
            vec![candidate(1, "rank one")],
        );
        nonzero.provider.provider_id = LOCAL_SENOCR_RASTER_PROVIDER_ID.to_owned();
        let state = test_state(vec![nonzero.clone()], Vec::new());
        let mut nonzero_session = CorrectionSession::open(&state, &nonzero.projection_id).unwrap();
        assert!(matches!(
            nonzero_session.select_candidate_rank(1),
            Err(CorrectionSessionError::CandidateSelectionUnsupported)
        ));

        let mut multiple = test_projection(
            "projection-multiple-candidates",
            "journal-multiple-candidates",
            "region-multiple-candidates",
            vec![candidate(0, "rank zero"), candidate(1, "rank one")],
        );
        multiple.provider.provider_id = LOCAL_SENOCR_RASTER_PROVIDER_ID.to_owned();
        let state = test_state(vec![multiple.clone()], Vec::new());
        let mut multiple_session =
            CorrectionSession::open(&state, &multiple.projection_id).unwrap();
        assert!(matches!(
            multiple_session.select_candidate_rank(0),
            Err(CorrectionSessionError::CandidateSelectionUnsupported)
        ));

        let external = test_projection(
            "projection-external-candidate",
            "journal-external-candidate",
            "region-external-candidate",
            vec![candidate(0, "external rank zero")],
        );
        let state = test_state(vec![external.clone()], Vec::new());
        let mut external_session =
            CorrectionSession::open(&state, &external.projection_id).unwrap();
        assert!(matches!(
            external_session.select_candidate_rank(0),
            Err(CorrectionSessionError::CandidateSelectionUnsupported)
        ));
    }

    #[test]
    fn empty_set_text_reset_and_cancel_are_distinct_no_write_actions() {
        let projection = test_projection(
            "projection-actions",
            "journal-actions",
            "region",
            vec![candidate(0, "provider original")],
        );
        let state = test_state(vec![projection.clone()], Vec::new());

        let mut empty_text = CorrectionSession::open(&state, &projection.projection_id).unwrap();
        assert_eq!(empty_text.effective_text(), Some("provider original"));
        assert!(empty_text.build_correction("untouched").unwrap().is_none());
        empty_text.set_text("").unwrap();
        assert_eq!(empty_text.effective_text(), Some(""));
        let set_text = empty_text
            .build_correction("correction-empty")
            .unwrap()
            .unwrap();
        assert_eq!(
            set_text.action,
            RegionCorrectionActionV1::SetText(String::new())
        );

        let mut reset = CorrectionSession::open(&state, &projection.projection_id).unwrap();
        reset.reset().unwrap();
        assert_eq!(reset.effective_text(), Some("provider original"));
        let reset_row = reset.build_correction("correction-reset").unwrap().unwrap();
        assert_eq!(reset_row.action, RegionCorrectionActionV1::Reset);
        assert_ne!(set_text.action, reset_row.action);

        let mut canceled = CorrectionSession::open(&state, &projection.projection_id).unwrap();
        canceled.set_text("draft to discard").unwrap();
        assert_eq!(canceled.effective_text(), Some("draft to discard"));
        canceled.on_focus_lost();
        assert!(canceled.is_dirty());
        canceled.cancel();
        assert!(canceled.is_cancelled());
        assert_eq!(canceled.text(), "draft to discard");
        assert_eq!(canceled.effective_text(), Some("provider original"));
        assert!(
            canceled
                .build_correction("correction-canceled")
                .unwrap()
                .is_none()
        );
        assert_eq!(state.region_corrections.len(), 0);

        let saved = RegionCorrectionV1 {
            correction_id: "saved-correction".to_owned(),
            projection_id: projection.projection_id.clone(),
            ink: projection.ink.clone(),
            action: RegionCorrectionActionV1::SetText("saved text".to_owned()),
        };
        let saved_state = test_state(vec![projection.clone()], vec![saved]);
        let mut saved_session =
            CorrectionSession::open(&saved_state, &projection.projection_id).unwrap();
        assert_eq!(saved_session.effective_text(), Some("saved text"));
        saved_session.set_text("later draft").unwrap();
        saved_session.cancel();
        assert_eq!(saved_session.effective_text(), Some("saved text"));
    }

    #[test]
    fn preparing_editor_from_provider_base_is_not_a_correction_until_text_changes() {
        let projection = test_projection(
            "projection-editor-base",
            "journal-editor-base",
            "region-editor-base",
            vec![candidate(0, "provider base")],
        );
        let state = test_state(vec![projection.clone()], Vec::new());
        let mut session = CorrectionSession::open(&state, &projection.projection_id).unwrap();

        session.prepare_editor_for_edit().unwrap();
        assert_eq!(session.text(), "provider base");
        assert_eq!(session.effective_text(), Some("provider base"));
        assert!(!session.is_dirty());
        assert!(session.build_correction("untouched-editor").unwrap().is_none());

        session.set_cursor_grapheme(3);
        session.insert_text("X").unwrap();
        assert_eq!(session.text(), "proXvider base");
        assert!(session.is_dirty());
        assert_eq!(
            session.build_correction("edited-base").unwrap().unwrap().action,
            RegionCorrectionActionV1::SetText("proXvider base".to_owned())
        );
    }

    #[test]
    fn correction_session_opens_only_the_latest_history_for_its_projection() {
        let first = test_projection(
            "projection-first",
            "journal-history",
            "region-first",
            vec![],
        );
        let second = test_projection(
            "projection-second",
            "journal-history",
            "region-second",
            vec![],
        );
        let first_set = RegionCorrectionV1 {
            correction_id: "first-set".to_owned(),
            projection_id: first.projection_id.clone(),
            ink: first.ink.clone(),
            action: RegionCorrectionActionV1::SetText("old".to_owned()),
        };
        let second_set = RegionCorrectionV1 {
            correction_id: "second-set".to_owned(),
            projection_id: second.projection_id.clone(),
            ink: second.ink.clone(),
            action: RegionCorrectionActionV1::SetText("other".to_owned()),
        };
        let first_reset = RegionCorrectionV1 {
            correction_id: "first-reset".to_owned(),
            projection_id: first.projection_id.clone(),
            ink: first.ink.clone(),
            action: RegionCorrectionActionV1::Reset,
        };
        let state = test_state(
            vec![first.clone(), second],
            vec![first_set, second_set, first_reset],
        );

        let session = CorrectionSession::open(&state, &first.projection_id).unwrap();

        assert_eq!(session.correction_history().len(), 2);
        assert!(matches!(
            session.latest_saved_action(),
            Some(RegionCorrectionActionV1::Reset)
        ));
        assert_eq!(session.text(), "");
        assert!(!session.is_dirty());
        assert!(session.build_correction("unchanged").unwrap().is_none());
    }

    #[test]
    fn correction_session_rejects_a_projection_from_another_project() {
        let projection = test_projection(
            "projection-project-bound",
            "journal-original",
            "region-project-bound",
            vec![],
        );
        let mut state = test_state(vec![projection.clone()], Vec::new());
        state.journal_id = "journal-other".to_owned();

        assert!(matches!(
            CorrectionSession::open(&state, &projection.projection_id),
            Err(CorrectionSessionError::ProjectionProjectMismatch)
        ));
    }

    #[test]
    fn correction_session_owns_projection_and_matching_history_after_snapshot_drops() {
        let projection = test_projection(
            "projection-owned-session",
            "journal-owned-session",
            "region-owned-session",
            vec![candidate(0, "durable provider text")],
        );
        let saved = RegionCorrectionV1 {
            correction_id: "owned-session-history".to_owned(),
            projection_id: projection.projection_id.clone(),
            ink: projection.ink.clone(),
            action: RegionCorrectionActionV1::SetText("prior saved text".to_owned()),
        };
        let mut session = {
            let state = test_state(vec![projection.clone()], vec![saved]);
            CorrectionSession::open(&state, &projection.projection_id).unwrap()
        };
        let frozen_projection = session.projection().clone();
        let frozen_ink = frozen_projection.ink.clone();

        assert_eq!(session.correction_history().len(), 1);
        assert_eq!(session.effective_text(), Some("prior saved text"));
        session.insert_text(" edited after source drop").unwrap();
        let correction = session
            .build_correction("owned-session-new-correction")
            .unwrap()
            .unwrap();

        assert_eq!(correction.projection_id, frozen_projection.projection_id);
        assert_eq!(correction.ink, frozen_ink);
        assert_eq!(session.projection(), &frozen_projection);
        assert_eq!(session.correction_history().len(), 1);
    }

    #[test]
    fn correction_session_undo_redo_restores_set_text_and_reset_modes() {
        let projection = test_projection("projection-undo", "journal-undo", "region", vec![]);
        let state = test_state(vec![projection.clone()], Vec::new());
        let mut session = CorrectionSession::open(&state, &projection.projection_id).unwrap();

        session.set_text("original draft").unwrap();
        session.reset().unwrap();
        assert_eq!(
            session.draft_action(),
            Some(RegionCorrectionActionV1::Reset)
        );
        assert!(session.undo());
        assert_eq!(session.text(), "original draft");
        assert_eq!(
            session.draft_action(),
            Some(RegionCorrectionActionV1::SetText(
                "original draft".to_owned()
            ))
        );
        assert!(session.redo());
        assert_eq!(session.text(), "");
        assert_eq!(
            session.draft_action(),
            Some(RegionCorrectionActionV1::Reset)
        );
        assert_eq!(
            session
                .build_correction("correction-reset-after-redo")
                .unwrap()
                .unwrap()
                .action,
            RegionCorrectionActionV1::Reset
        );
    }

    #[test]
    fn editor_preserves_nfc_nfd_and_uses_grapheme_safe_selection_and_deletion() {
        let nfd = "e\u{301}";
        let nfc = "\u{e9}";
        let mut editor = CorrectionTextEditor::new(nfd).unwrap();
        assert_eq!(editor.grapheme_count(), 1);
        editor.set_cursor_grapheme(1);
        editor.insert_text("!").unwrap();
        assert_eq!(editor.text(), "e\u{301}!");
        assert!(editor.undo());
        assert_eq!(editor.text(), nfd);

        let mut emoji = CorrectionTextEditor::new("A👩‍💻B\n").unwrap();
        assert_eq!(emoji.grapheme_count(), 4);
        emoji.select_graphemes(1, 2);
        assert!(emoji.delete_backward().unwrap());
        assert_eq!(emoji.text(), "AB\n");
        assert_eq!(emoji.cursor_grapheme(), 1);
        assert!(emoji.insert_newline().unwrap());
        assert_eq!(emoji.text(), "A\nB\n");

        let composed = CorrectionTextEditor::new(nfc).unwrap();
        assert_eq!(composed.grapheme_count(), 1);
        assert_eq!(composed.text().as_bytes(), nfc.as_bytes());
    }

    #[test]
    fn multiline_caret_and_vertical_selection_stay_on_grapheme_boundaries() {
        let mut editor = CorrectionTextEditor::new("ab👩‍💻\nxy\n").unwrap();
        assert_eq!(editor.grapheme_count(), 7);
        editor.set_cursor_grapheme(2);
        editor.move_cursor_down(false);
        assert_eq!(editor.cursor_grapheme(), 6);
        editor.move_cursor_up(false);
        assert_eq!(editor.cursor_grapheme(), 2);
        editor.move_cursor_down(true);
        assert_eq!(editor.selection_graphemes(), Some(2..6));
        editor.delete_backward().unwrap();
        assert_eq!(editor.text(), "ab\n");
    }

    #[test]
    fn wrapped_vertical_caret_and_shift_selection_stay_on_grapheme_boundaries() {
        let text = format!("a👩‍💻{}", "b".repeat(40));
        let mut editor = CorrectionTextEditor::new(&text).unwrap();
        assert_eq!(editor.grapheme_count(), 42);
        assert_eq!(editor.visual_line_ranges(38), vec![0..38, 38..42]);

        editor.set_cursor_grapheme(39);
        editor.move_cursor_up_wrapped(38, false);
        assert_eq!(editor.cursor_grapheme(), 1);
        editor.move_cursor_down_wrapped(38, false);
        assert_eq!(editor.cursor_grapheme(), 39);

        editor.set_cursor_grapheme(1);
        editor.move_cursor_down_wrapped(38, true);
        assert_eq!(editor.cursor_grapheme(), 39);
        assert_eq!(editor.selection_graphemes(), Some(1..39));
        assert!(editor.selection_graphemes().is_some_and(|range| {
            range.start <= editor.grapheme_count() && range.end <= editor.grapheme_count()
        }));
    }

    #[test]
    fn editor_ime_preedit_is_transient_cancelable_and_commits_once() {
        let mut editor = CorrectionTextEditor::new("eX").unwrap();
        editor.select_graphemes(0, 1);
        editor.begin_preedit();
        editor.update_preedit("e\u{301}").unwrap();
        assert_eq!(editor.text(), "eX");
        assert_eq!(editor.preview_text().unwrap(), "e\u{301}X");
        editor.update_preedit("e\u{301}").unwrap();
        assert_eq!(editor.preview_text().unwrap(), "e\u{301}X");
        assert!(editor.commit_preedit().unwrap());
        assert_eq!(editor.text(), "e\u{301}X");
        assert!(!editor.commit_preedit().unwrap());
        assert!(editor.undo());
        assert_eq!(editor.text(), "eX");

        editor.set_cursor_grapheme(1);
        editor.update_preedit("draft").unwrap();
        assert!(editor.cancel_preedit());
        assert_eq!(editor.text(), "eX");
    }

    #[test]
    fn authoritative_ime_commit_replaces_preedit_once_without_normalizing_unicode() {
        let mut editor = CorrectionTextEditor::new("NFD e\u{301}").unwrap();
        editor.set_cursor_grapheme(editor.grapheme_count());
        editor.update_preedit("漢").unwrap();
        assert_eq!(editor.text(), "NFD e\u{301}");
        assert_eq!(editor.preview_text().unwrap(), "NFD e\u{301}漢");
        assert!(editor.commit_ime_text("漢").unwrap());
        assert_eq!(editor.text(), "NFD e\u{301}漢");
        assert!(!editor.has_preedit());
    }

    #[test]
    fn editor_undo_redo_is_bounded_and_keeps_text_limit_from_journal_validator() {
        let mut editor = CorrectionTextEditor::new("").unwrap();
        for _ in 0..(MAX_CORRECTION_UNDO_STEPS + 4) {
            editor.insert_text("x").unwrap();
        }
        assert_eq!(editor.undo_depth(), MAX_CORRECTION_UNDO_STEPS);
        let mut undo_count = 0;
        while editor.undo() {
            undo_count += 1;
        }
        assert_eq!(undo_count, MAX_CORRECTION_UNDO_STEPS);
        assert_eq!(editor.text(), "xxxx");
        assert!(editor.redo());
        assert_eq!(editor.text(), "xxxxx");

        let oversized = "x".repeat(crate::journal::MAX_JOURNAL_TEXT_BYTES + 1);
        assert!(editor.set_text(&oversized).is_err());
    }
}
