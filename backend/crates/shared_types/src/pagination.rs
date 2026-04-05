use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u32,

    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    20
}

impl PaginationParams {
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.limit
    }

    pub fn validate(&mut self) {
        if self.page == 0 {
            self.page = 1;
        }
        if self.limit == 0 || self.limit > 100 {
            self.limit = 20;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    pub page: u32,
    pub limit: u32,
    pub total: i64,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_prev: bool,
}

impl PaginationMeta {
    pub fn new(page: u32, limit: u32, total: i64) -> Self {
        let total_pages = ((total as f64) / (limit as f64)).ceil() as u32;

        Self {
            page,
            limit,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        }
    }
}

impl<T> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, params: &PaginationParams, total: i64) -> Self {
        Self {
            data,
            pagination: PaginationMeta::new(params.page, params.limit, total),
        }
    }
}
