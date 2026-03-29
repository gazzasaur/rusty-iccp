pub mod error;

use async_trait::async_trait;

use error::*;
use rusty_mms::MmsObjectName;

#[async_trait]
pub trait IccpClient: Send + Sync + Clone {
    // get_data_value_names
    // get_data_value
    // set_data_value
    // get_data_value_type

    // get_data_set_names
    // get_data_set_element_names - This is a dataset operation
    // create_data_set
    // delete_data_set - Drop
    // get_data_set_element_values - This is a dataset operation
    // set_data_set_element_values - This is a dataset operation

    // start_transfer - This is a dataset operation
    // stop_transfer - Drop
    // get_next_ds_transfer_set_value - Hide This

    // select
    // operate
    // get_tag_value
    // set_tag_value

    // fn fetch_transfer_report
}

pub enum QualityFlag {
}

pub enum IccpData {
    RealQ(f32, Vec<QualityFlag>),
}

#[async_trait]
pub trait IccpServer: Send + Sync + Clone {
    // get_data_value_names
    // get_data_value
    // set_data_value
    // get_data_value_type

    // get_data_set_names
    // get_data_set_element_names
    // create_data_set
    // delete_data_set
    // get_data_set_element_values
    // set_data_set_element_values

    // start_transfer
    // stop_transfer
    // get_next_ds_transfer_set_value

    // select
    // operate
    // get_tag_value
    // set_tag_value

    // fn fetch_transfer_report
}